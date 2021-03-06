package tsec.signature.imports

import cats.effect.Sync
import tsec.signature.core.{CryptoSignature, SigAlgoTag, SignaturePrograms}

sealed abstract case class JCASigner[F[_]: Sync, A: SigAlgoTag](
    alg: JCASigInterpreter[F, A]
) extends SignaturePrograms[F, A] {

  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]
  val algebra: JCASigInterpreter[F, A] = alg
}

object JCASigner {

  def apply[F[_]: Sync, A: SigAlgoTag](implicit s: JCASigInterpreter[F, A]): JCASigner[F, A] =
    new JCASigner[F, A](s) {}

  implicit def genSigner[F[_]: Sync, A: SigAlgoTag](
      implicit s: JCASigInterpreter[F, A]
  ): JCASigner[F, A] = apply[F, A]

  def sign[F[_]: Sync, A: SigAlgoTag](content: Array[Byte], p: SigPrivateKey[A])(
      implicit js: JCASigner[F, A]
  ): F[CryptoSignature[A]] = js.sign(content, p)

  def verifyK[F[_]: Sync, A: SigAlgoTag](toSign: Array[Byte], signed: Array[Byte], k: SigPublicKey[A])(
      implicit js: JCASigner[F, A]
  ): F[Boolean] =
    js.verifyK(toSign, signed, k)

  def verifyKI[F[_]: Sync, A: SigAlgoTag](toSign: Array[Byte], signed: CryptoSignature[A], k: SigPublicKey[A])(
      implicit js: JCASigner[F, A]
  ): F[Boolean] = js.verifyKI(toSign, signed, k)

  def verifyC[F[_]: Sync, A: SigAlgoTag](toSign: Array[Byte], signed: Array[Byte], c: SigCertificate[A])(
      implicit js: JCASigner[F, A]
  ): F[Boolean] = js.verifyC(toSign, signed, c)

  def verifyCI[F[_]: Sync, A: SigAlgoTag](toSign: Array[Byte], signed: CryptoSignature[A], c: SigCertificate[A])(
      implicit js: JCASigner[F, A]
  ): F[Boolean] = js.verifyCI(toSign, signed, c)

}
