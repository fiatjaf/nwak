import cats.data.*
import cats.effect.*
import cats.effect.syntax.all.*
import cats.syntax.all.*
import fs2.concurrent.*
import fs2.dom.{Event as _, *}
import org.http4s.Uri
import org.http4s.syntax.all.*
import calico.router.*
import snow.*
import scala.concurrent.duration.*

case class Store(
    input: SignallingRef[IO, String],
    result: SignallingRef[IO, Result],
    nip07signer: SignallingRef[IO, Resource[IO,NIP07Signer[IO]]]
)

object Store {
  def apply(window: Window[IO]): Resource[IO, Store] = {
    val key = "nak-input"

    def uriFromInput(input: String): Uri =
      uri"".withFragment("/" ++ input)
    
    def inputFromUri(uri: Uri): String =
      uri.fragment.map(_.stripPrefix("/")).map(Uri.decode(_)).getOrElse("")

    for {
      router <- Router(window).toResource
      // if the browser has been loaded with a url like /#/npub1g4f...
      // then we will start our textarea off with that value
      urlparam <- router.location.get.map(inputFromUri).toResource
      input <- SignallingRef[IO].of(urlparam).toResource
      result <- SignallingRef[IO, Result](Left("")).toResource

      // start with nip07 debugging client
      nip07client <- SignallingRef[IO].of(NIP07.mkDebuggingSigner()).toResource
      
      _ <- window.localStorage
        .events(window)
        .foreach {
          case Storage.Event.Updated(`key`, _, value, _) =>
            input.set(value)
          case _ => IO.unit
        }
        .compile
        .drain
        .background

      _ <- input.changes.discrete
        .map(_.trim)
        .evalTap(input => IO.cede *> window.localStorage.setItem(key, input))
        .evalTap{
          input => 
            router.location.get.map(inputFromUri)
              // for security we will not update the url if the input is
              // an nsec since we can easily detect an nsec. However, if it
              // is a generic 32-byte string, it could be a public key or a
              // private key, so we risk it and put it in the url to make for
              // easier testing/debugging. But maybe this is the wrong decision?
              .map(_ == input || input.startsWith("nsec")).ifM(
                ifTrue = IO.unit,
                ifFalse = router.navigate(uriFromInput(input))
              )
        }
        .map(input => Parser.parseInput(input))
        .evalTap(parsed => result.set(parsed))
        .compile
        .drain
        .background

      _ <- router.location.changes.discrete
        .map(inputFromUri)
        .evalTap{
          proposedInput => input.get.map(_.trim)
            .map(_ == proposedInput).ifM(
              ifTrue = IO.unit,
              ifFalse =  input.set(proposedInput)
            )
        }
        .compile
        .drain
        .background
    } yield Store(input, result, nip07client)
  }
    
}
