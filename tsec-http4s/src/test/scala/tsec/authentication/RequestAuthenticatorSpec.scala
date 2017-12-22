package tsec.authentication

import cats.data.OptionT
import cats.effect.IO
import cats.effect.implicits._
import io.circe.Json
import org.http4s.dsl.io._
import org.http4s.circe._
import org.http4s._
import cats.syntax.all._
import org.http4s.implicits._
import io.circe.syntax._
import io.circe.generic.auto._
import tsec.authorization.BasicRBAC

class RequestAuthenticatorSpec extends AuthenticatorSpec {

  def requestAuthTests[A](title: String, authSpec: AuthSpecTester[A]) {

    behavior of "SecuredRequests: " + title

    val dummyBob = DummyUser(0)

    val requestAuth = SecuredRequestHandler(authSpec.auth)

    //Add bob to the db
    authSpec.dummyStore.put(dummyBob).unsafeRunSync()

    val onlyAdmins = BasicRBAC[IO, DummyRole, DummyUser, A](DummyRole.Admin)
    val everyone   = BasicRBAC.all[IO, DummyRole, DummyUser, A]

    val testService: HttpService[IO] = requestAuth {
      case request @ GET -> Root / "api" asAuthed hi =>
          Ok(hi.asJson)

    }

    val adminService: HttpService[IO] = requestAuth.authorized(onlyAdmins) {
      case request @ GET -> Root / "api" asAuthed hi =>
          Ok(hi.asJson)
    }

    val everyoneService: HttpService[IO] = requestAuth.authorized(everyone) {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
      }


    // Only admins can post
    val postingService: HttpService[IO] = requestAuth.authorized(onlyAdmins) {
      case request @ POST -> Root / "api" asAuthed hi =>
          Ok(hi.asJson)
     }

    // Everyone can view
    val gettingService: HttpService[IO] = requestAuth.authorized(everyone) {
      case request @ GET -> Root / "api" asAuthed hi =>
          Ok(hi.asJson)
      }

    // Composed
    val postingAndGettingService = {
      postingService <+> gettingService
    }


    it should "TryExtractRaw properly" in {

      val response: OptionT[IO, Option[String]] = for {
        auth <- requestAuth.authenticator.create(dummyBob.id)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
      } yield authSpec.auth.extractRawOption(embedded)
      response
        .getOrElse(None)
        .unsafeRunSync()
        .isDefined mustBe true
    }

    it should "Return a proper deserialized user" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- requestAuth.authenticator.create(dummyBob.id)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "fail on an expired token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth    <- requestAuth.authenticator.create(dummyBob.id)
        expired <- authSpec.expireAuthenticator(auth)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), expired)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "work on a renewed token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth    <- requestAuth.authenticator.create(dummyBob.id)
        expired <- authSpec.expireAuthenticator(auth)
        renewed <- authSpec.auth.renew(expired)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "fail on a timed out token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth     <- requestAuth.authenticator.create(dummyBob.id)
        timedOut <- authSpec.timeoutAuthenticator(auth)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), timedOut)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "work on a refreshed token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth    <- requestAuth.authenticator.create(dummyBob.id)
        expired <- authSpec.timeoutAuthenticator(auth)
        renewed <- authSpec.auth.refresh(expired)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "Reject an invalid token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- authSpec.wrongKeyAuthenticator
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    //note: we feed it "discarded" because stateless tokens rely on this.
    it should "Fail on a discarded token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth      <- requestAuth.authenticator.create(dummyBob.id)
        discarded <- requestAuth.authenticator.discard(auth)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), discarded)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "authorize for an allowed endpoint" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- requestAuth.authenticator.create(dummyBob.id)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- everyoneService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "not authorize for a gated endpoint" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- requestAuth.authenticator.create(dummyBob.id)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- adminService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "allow messages service to GET" in {
      val response: OptionT[IO, Response[IO]] = for {
          auth <- requestAuth.authenticator.create(dummyBob.id)
          embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
          res <- postingAndGettingService(embedded)
        } yield res

      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Ok

    }
  }

}
