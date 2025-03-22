import cats.data.*
import cats.effect.*
import cats.effect.syntax.all.*
import cats.syntax.all.*
import fs2.concurrent.*
import fs2.dom.{Event as _, *}
import org.http4s.Uri
import org.http4s.syntax.all.*
import snow.*
import scala.concurrent.duration.*
import scalajs.js
import scalajs.js.annotation.JSGlobal
import scala.scalajs.js.Dynamic.global
import io.circe.parser.*
import io.circe.syntax.*
import scala.scalajs.js.JSON
import scoin.XOnlyPublicKey
import scoin.PrivateKey

/**
  * basic NIP07 client for signing events
  * TODO: upstream to snow
  */
trait NIP07Signer[F[_]]:
  def publicKeyHex: F[String]
  def publicKey: F[scoin.XOnlyPublicKey]
  def signEvent(unsignedEvent: Event): F[Event]
  def isDebuggingSigner: F[Boolean]

object NIP07:

  /** check if nip07 (`window.nostr`) is availabe in the browser
   *  note: this will semantically block until the page is done loading
   * */
  def isAvailable: IO[Boolean] = waitForLoad *> IO{
    val nostr = global.window.nostr
    !js.isUndefined(nostr)
  }

  def apply(window: Window[IO]): Resource[IO,NIP07Signer[IO]] 
    = IO(new NIP07SignerImplIO(window)).toResource

  /**
    * create a NIP07 signer `Resource`
    */
  def mkSigner(window: Window[IO]) = apply(window)

  def mkDebuggingSigner(
    privkey: scoin.PrivateKey = Utils.keyOne
  ): Resource[IO,NIP07Signer[IO]] = 
    Resource.pure(new NIP07DebuggingSignerIO(privkey))

  // Create an fs2 Stream that registers an event listener on dom.window for the "load" event.
  private def loadEventStream: fs2.Stream[IO, org.scalajs.dom.Event] =
    fs2.Stream.eval(IO.async_[org.scalajs.dom.Event] { cb =>
      lazy val listener: js.Function1[org.scalajs.dom.Event, Unit] = { 
        (e: org.scalajs.dom.Event) =>
          // Once the event fires, remove the listener and signal completion.
          org.scalajs.dom.window.removeEventListener("load", listener)
          cb(Right(e))
      }
      org.scalajs.dom.window.addEventListener("load", listener)
    })

  // Wait until the page is loaded; if already loaded, do nothing.
  private def waitForLoad: IO[Unit] =
    if (org.scalajs.dom.document.readyState == "complete") IO.unit
    else loadEventStream.head.compile.drain

///////////
// implementations
//////////

class NIP07SignerImplIO(window: Window[IO]) extends NIP07Signer[IO]:
  def isDebuggingSigner: IO[Boolean] = IO(false)
  def publicKeyHex: IO[String] = 
    IO.fromPromise(IO(_nostr.getPublicKey()))

  def publicKey: IO[XOnlyPublicKey] =
      publicKeyHex
      .map(scoin.ByteVector32.fromValidHex)
      .map(scoin.XOnlyPublicKey(_))

  def signEvent(unsignedEvent: Event): IO[Event] =
    IO(unsignedEvent.asJson.noSpaces)
      .map(JSON.parse(_).asInstanceOf[js.Object])
      .map(_nostr.signEvent)
      .flatMap(promise => IO.fromPromise(IO(promise)))
      .map(JSON.stringify(_))
      .map(parse)
      .flatMap(IO.fromEither)
      .map(_.as[Event])
      .flatMap(IO.fromEither)

class NIP07DebuggingSignerIO(privkey: scoin.PrivateKey) extends NIP07Signer[IO]:
  def isDebuggingSigner: IO[Boolean] = IO(true)
  def publicKeyHex: IO[String] = IO(privkey).map(_.publicKey.xonly.toHex)

  def publicKey: IO[XOnlyPublicKey] =
    publicKeyHex
    .map(scoin.ByteVector32.fromValidHex)
    .map(scoin.XOnlyPublicKey(_))

  def signEvent(unsignedEvent: Event): IO[Event] = IO(unsignedEvent.sign(privkey))

// scalajs glue
@js.native
@JSGlobal("nostr")
private object _nostr extends js.Object:
  def getPublicKey(): js.Promise[String] = js.native
  def signEvent(event: js.Object): js.Promise[js.Object] = js.native