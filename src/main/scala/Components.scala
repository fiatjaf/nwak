import cats.data.{Store as *, *}
import cats.effect.*
import cats.effect.syntax.all.*
import cats.syntax.all.*
import fs2.concurrent.*
import fs2.dom.{Event as _, *}
import io.circe.parser.*
import io.circe.syntax.*
import calico.*
import calico.html.io.{*, given}
import calico.syntax.*
import calico.frp.given
import scodec.bits.ByteVector
import scoin.*
import snow.*

import org.http4s.syntax.literals.uri

import Utils.*

object Components {
  def render32Bytes(
      store: Store,
      bytes32: ByteVector32
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      cls := "flex flex-col gap-2",
      entry("canonical hex", bytes32.toHex),
      "if this is a public key:",
      div(
        cls := "mt-2 pl-2 mb-2",
        entry(
          "npub",
          NIP19.encode(XOnlyPublicKey(bytes32)),
          Some(
            selectable(
              store,
              NIP19.encode(XOnlyPublicKey(bytes32))
            )
          )
        ),
        nip19_21(
          store,
          "nprofile",
          NIP19.encode(ProfilePointer(XOnlyPublicKey(bytes32)))
        )
      ),
      "if this is a private key:",
      div(
        cls := "pl-2 mb-2",
          (store.nip07signer: Signal[IO,Resource[IO,NIP07Signer[IO]]]).map{ signer =>
            signer.use(_.publicKey).map(_ == PrivateKey(bytes32).publicKey.xonly)
            .toResource.flatMap{ alreadyUsingThisPubkey =>
                fixableEntry(
                  "nsec",
                  NIP19.encode(PrivateKey(bytes32)),
                  fixWith = (
                    IO(PrivateKey(bytes32))
                    .map(NIP07.mkDebuggingSigner).flatMap(store.nip07signer.set)
                  ),
                  buttonLabel = "use as debugging key",
                  selectLink = Some(
                    selectable(
                      store,
                      NIP19.encode(PrivateKey(bytes32))
                    )
                  ),
                  enable = !alreadyUsingThisPubkey
                )
            }
          },
        entry(
          "npub",
          NIP19.encode(PrivateKey(bytes32).publicKey.xonly),
          Some(
            selectable(
              store,
              NIP19.encode(PrivateKey(bytes32).publicKey.xonly)
            )
          )
        ),
        nip19_21(
          store,
          "nprofile",
          NIP19.encode(ProfilePointer(PrivateKey(bytes32).publicKey.xonly))
        )
      ),
      "if this is an event id:",
      div(
        cls := "pl-2 mb-2",
        nip19_21(
          store,
          "nevent",
          NIP19.encode(EventPointer(bytes32.toHex))
        )
      ),
    )

  def renderEventPointer(
      store: Store,
      evp: snow.EventPointer
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      cls := "text-md flex flex-col gap-2",
      entry(
        "event id (hex)",
        evp.id,
        Some(selectable(store, evp.id))
      ),
      relayHints(store, evp.relays),
      evp.author.map { pk =>
        entry("author (pubkey hex)", pk.value.toHex)
      },
      evp.kind.map { kind =>
        entry("kind", kind.toString)
      },
      nip19_21(store, "nevent", NIP19.encode(evp)),
    )

  def renderProfilePointer(
      store: Store,
      pp: snow.ProfilePointer,
      sk: Option[PrivateKey] = None
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      cls := "text-md flex flex-col gap-2",
      sk.map { k =>
        entry(
          "private key (hex)",
          k.value.toHex,
          Some(selectable(store, k.value.toHex))
        )
      },
      sk.map { k =>
        (store.nip07signer: Signal[IO,Resource[IO,NIP07Signer[IO]]]).map{ signer =>
          signer.use(_.publicKey).map(_ == k.publicKey.xonly).toResource.flatMap{
            alreadyUsingThisPubkey => 
              fixableEntry(
                "nsec",
                NIP19.encode(k),
                fixWith = (
                  IO(NIP07.mkDebuggingSigner(k)).flatMap(store.nip07signer.set)
                ),
                buttonLabel = "use as debugging key",
                selectLink = Some(selectable(store, NIP19.encode(k))),
                enable = !alreadyUsingThisPubkey
              )
          }
        }
      },
      entry(
        "public key (hex)",
        pp.pubkey.value.toHex,
        Some(selectable(store, pp.pubkey.value.toHex))
      ),
      relayHints(
        store,
        pp.relays,
        dynamic = if sk.isDefined then false else true
      ),
      entry(
        "npub",
        NIP19.encode(pp.pubkey),
        Some(selectable(store, NIP19.encode(pp.pubkey)))
      ),
      nip19_21(store, "nprofile", NIP19.encode(pp))
    )

  def renderAddressPointer(
      store: Store,
      addr: snow.AddressPointer
  ): Resource[IO, HtmlDivElement[IO]] = {
    val nip33atag =
      s"${addr.kind}:${addr.author.value.toHex}:${addr.d}"

    div(
      cls := "text-md flex flex-col gap-2",
      entry("author (pubkey hex)", addr.author.value.toHex),
      entry("identifier (d tag)", addr.d),
      entry("kind", addr.kind.toString),
      relayHints(store, addr.relays),
      nip19_21(store, "naddr", NIP19.encode(addr)),
      entry("nip33 'a' tag", nip33atag, Some(selectable(store, nip33atag)))
    )
  }

  def renderEvent(
      store: Store,
      event: Event
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      cls := "text-md flex flex-col gap-2",
      if event.isValid then
        Some(renderSubmitEvent(store, event))
      else None,
      if event.pubkey.isEmpty then
        Some(
          div(
            cls := "flex items-center",
            entry("missing", "pubkey"),
            button(
              Styles.buttonSmall,
              "fill with a debugging key",
              onClick --> (_.foreach { _ =>
                store.input.set(
                  event
                    .copy(pubkey = Some(keyOne.publicKey.xonly))
                    .asJson
                    .printWith(jsonPrinter)
                )
              })
            )
          )
        )
      else None,
      if event.id.isEmpty then
        Some(
          div(
            cls := "flex items-center",
            entry("missing", "id"),
            if event.pubkey.isDefined then
              Some(
                button(
                  Styles.buttonSmall,
                  "fill id",
                  onClick --> (_.foreach(_ =>
                    store.input.set(
                      event
                        .copy(id = Some(event.hash.toHex))
                        .asJson
                        .printWith(jsonPrinter)
                    )
                  ))
                )
              )
            else None
          )
        )
      else None,
      if event.sig.isEmpty then
        Some(
          div(
            cls := "flex items-center",
            entry("missing", "sig"),
            if event.id.isDefined && event.pubkey == Some(
                keyOne.publicKey.xonly
              )
            then
              Some(
                button(
                  Styles.buttonSmall,
                  "sign",
                  onClick --> (_.foreach(_ =>
                    store.nip07signer.get.flatMap(_.use { signer =>
                      for
                        pubkey <- signer.publicKey
                        preparedEvent <- IO(event.copy(pubkey = Some(pubkey), id = None))
                        _ <- signer.signEvent(preparedEvent).flatMap{ signedEvent =>
                          store.input.set(
                          signedEvent
                          .asJson
                          .printWith(jsonPrinter)
                        )
                      }
                      yield ()
                    })
                  ))
                )
              )
            else None
          )
        )
      else None,
      entry("serialized event", event.serialized),
      entry("implied event id", event.hash.toHex),
      event.id == Some(event.hash.toHex) match {
        case true => entry(
          "implied event id matches given event id?",
          "yes"
        )
        case false => fixableEntry(
          "implied event id matches given event id?",
          "no",
          fixWith = store.input.set(
            event
              .copy(id = Some(event.hash.toHex))
              .asJson
              .printWith(jsonPrinter)
          )
        )
      },
      event.isValid match {
        case true => entry(
          "is signature valid?",
          "yes"
        )
        case false => fixableEntry(
          "is signature valid?",
          "no",
          buttonLabel = "sign and fix",
          notice = "note: fixing will update pubkey, id, and signature",
          fixWith = store.nip07signer.get.flatMap(_.use { signer =>
            for
              pubkey <- signer.publicKey
              preparedEvent <- IO(event.copy(pubkey = Some(pubkey), id = None))
              _ <- signer.signEvent(preparedEvent).flatMap{ signedEvent =>
                store.input.set(
                signedEvent
                .asJson
                .printWith(jsonPrinter)
              )
            }
            yield ()
          })
        )
      },
      // ensure timetsamp is reasonable (before Jan 1, 3000), offer to fix if not
      (event.created_at >= 0L && event.created_at <= 32_503_680_000L) match
        case true => None // no need to show anything
        case false => Some(
          fixableEntry(
            "is timestamp valid?",
            "no",
            buttonLabel = "fix with current time",
            notice = "note: fixing will update id",
            fixWith = store.input.set(
              event
                .copy(created_at = new java.util.Date().getTime() / 1000)
                .asJson
                .printWith(jsonPrinter)
            )
          )
        ),
      if event.kind >= 30000 && event.kind < 40000 then
        event.pubkey
          .map(author =>
            nip19_21(
              store,
              "naddr",
              NIP19.encode(
                AddressPointer(
                  d = event.tags
                    .collectFirst { case "d" :: v :: _ => v }
                    .getOrElse(""),
                  kind = event.kind,
                  author = author,
                  relays = List.empty
                )
              )
            )
          )
      else
        event.id.map(id =>
          nip19_21(
            store,
            "nevent",
            NIP19.encode(EventPointer(id, author = event.pubkey, kind = Some(event.kind)))
          )
        )
    )

  def renderSubmitEvent(
    store: Store,
    event: Event
  ): Resource[IO, HtmlDivElement[IO]] =
    if(event.isValid) then
      SignallingRef[IO].of(Option.empty[Messages.FromRelay.OK]).toResource.flatMap {
        relayReply =>
          div(
            cls := "flex items-center space-x-3",
            span(cls := "font-bold", "submit to relay? "),
            div(
              cls := "flex flex-wrap justify-between max-w-xl gap-2",
              renderSubmitToRelay(store,event,"ws://localhost:10547"),
              renderSubmitToRelay(store,event,"wss://relay.damus.io"),
              renderInputCustomRelay(store,event)
            )
          )
      }
    else
      div("invalid event; cannot yet submit to relay")

  def renderSubmitToRelay(
    store: Store,
    validEvent: Event,
    initialRelayUri: String,
    submitOnFirstLoad: Boolean = false
  ): Resource[IO, HtmlDivElement[IO]] =
    (
      SignallingRef[IO].of(false).toResource,
      SignallingRef[IO].of(Option.empty[Messages.FromRelay.OK]).toResource
    ).tupled.flatMap {
      (awaitingReply, relayReply) =>
        val submitEvent =
          IO.fromEither(org.http4s.Uri.fromString(initialRelayUri))
            .toResource
            .flatMap(Relay.mkResourceForIO(_))
            .use(relay =>
              awaitingReply.set(true)
              *> (relay.submitEvent(validEvent).option >>= relayReply.set)
              <* (awaitingReply.set(false))
            ).recoverWith{
              case e: java.io.IOException =>
                relayReply.set(Some(Messages.FromRelay.OK("",false,"websocket connection error")))
                *> awaitingReply.set(false)
            }

        val buttonLabel = (awaitingReply: Signal[IO,Boolean]).flatMap {
          case false => relayReply.map {
            case None => s"$initialRelayUri"
            case Some(Messages.FromRelay.OK(_,accepted,_))
              if accepted => s"$initialRelayUri - \u2705"
            case Some(Messages.FromRelay.OK(_,accepted,message))
              if !accepted => s"$initialRelayUri - FAIL - $message"
            case _ => s"$initialRelayUri"
          }
          case true => relayReply.map(_ => s"$initialRelayUri - ...")
        }

        val isConnectionError = relayReply.map{
          case Some(Messages.FromRelay.OK(_,accepted, msg))
            if(!accepted && msg.contains("connection error")) => true
          case _ => false
        }

        val onFirstLoad = if(submitOnFirstLoad) then submitEvent else IO.unit

        onFirstLoad.background *>
        div(
          isConnectionError.map{
            case false =>
              div(
                cls := "flex items-center rounded",
                button(
                  Styles.buttonSmall,
                  buttonLabel,
                  onClick --> (_.foreach{_ => submitEvent }),
                  disabled <-- awaitingReply
                )
              )
            case true =>
              renderInputCustomRelay(store,validEvent, initialButtonLabel = "websocket connection error")
          }
        )
    }

  def renderInputCustomRelay(
    store: Store,
    validEvent: Event,
    initialButtonLabel: String = "custom relay"
  ): Resource[IO, HtmlDivElement[IO]] = (
    SignallingRef[IO].of(false).toResource,
    SignallingRef[IO].of("").toResource
  ).flatMapN{
    (isActive, rawRelayUri) =>
      div(
        (isActive: Signal[IO,Boolean]).map {
          case true =>
            div(
              rawRelayUri.map {
                case url if url.isEmpty =>
                    input.withSelf { self =>
                      (
                        cls := "w-full py-1 px-2 text-sm font-mono rounded bg-glade-green-50 border border-glade-green-200 text-gray-900",
                        defaultValue := "ws://localhost:10547",
                        onKeyPress --> (_.foreach(evt =>
                          evt.key match {
                            case "Enter" =>
                              self.value.get
                              .map{
                                case url if url.isEmpty => url
                                case url if url.contains("://") => url
                                case url if !url.contains("://") && url.nonEmpty => url.prependedAll("wss://")
                                case _ => ""
                              }.flatMap(url =>
                                if url.contains("://") then
                                  rawRelayUri.set(url)
                                else IO.unit
                              )
                            case _ => IO.unit
                          }
                        ))
                      )
                    }
                case url =>
                    renderSubmitToRelay(store,validEvent,initialRelayUri = url, submitOnFirstLoad = true)
              }
            )
          case false =>
            div(
              cls := "flex items-center rounded",
              button(
                Styles.buttonSmall,
                initialButtonLabel,
                onClick --> (_.foreach{_ => isActive.set(true) }),
              )
            )
        }
      )
  }

  private def fixableEntry(
    key: String,
    value: String,
    fixWith: => IO[Unit],
    selectLink: Option[Resource[IO, HtmlSpanElement[IO]]] = None,
    buttonLabel: String = "fix",
    notice: String = "",
    enable: Boolean = true // whether to actually dispay the fix stuff
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      cls := "flex items-center space-x-3",
      span(cls := "font-bold", key + " "),
      span(cls := "font-mono max-w-xl break-all", value),
      selectLink,
      if enable then
        Some(button(
          buttonLabel,
          Styles.buttonSmall,
          onClick --> (_.foreach{_ => fixWith})
        )) 
      else None,
      if(notice.nonEmpty && enable) then
        Some(span(cls := "font-mono max-w-xl break-all", " " + notice))
      else None

    )

  private def entry(
      key: String,
      value: String,
      selectLink: Option[Resource[IO, HtmlSpanElement[IO]]] = None
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      cls := "flex items-center space-x-3",
      span(cls := "font-bold", key + " "),
      span(cls := "font-mono max-w-xl break-all", value),
      selectLink
    )

  private def nip19_21(
      store: Store,
      key: String,
      code: String
  ): Resource[IO, HtmlDivElement[IO]] =
    div(
      span(cls := "font-bold", key + " "),
      span(cls := "font-mono break-all", code),
      selectable(store, code),
      a(
        href := "nostr:" + code,
        external
      )
    )

  private def relayHints(
      store: Store,
      relays: List[String],
      dynamic: Boolean = true
  ): Resource[IO, HtmlDivElement[IO]] =
    if !dynamic && relays.isEmpty then div("")
    else
      SignallingRef[IO].of(false).toResource.flatMap { active =>
        div(
          cls := "flex items-center space-x-3",
          span(cls := "font-bold", "relay hints "),
          if relays.size == 0 then div("")
          else
            // displaying each relay hint
            div(
              cls := "flex flex-wrap max-w-xl",
              relays
                .map(url =>
                  div(
                    cls := "font-mono flex items-center rounded py-0.5 px-1 mr-1 mb-1 bg-orange-100",
                    url,
                    // removing a relay hint by clicking on the x
                    div(
                      cls := "cursor-pointer ml-1 text-rose-600 hover:text-rose-300",
                      onClick --> (_.foreach(_ => {
                        store.result.get.flatMap(result =>
                          store.input.set(
                            result
                              .map {
                                case a: AddressPointer =>
                                  NIP19
                                    .encode(
                                      a.copy(relays =
                                        relays.filterNot(_ == url)
                                      )
                                    )
                                case p: ProfilePointer =>
                                  NIP19
                                    .encode(
                                      p.copy(relays =
                                        relays.filterNot(_ == url)
                                      )
                                    )
                                case e: EventPointer =>
                                  NIP19
                                    .encode(
                                      e.copy(relays =
                                        relays.filterNot(_ == url)
                                      )
                                    )
                                case r => ""
                              }
                              .getOrElse("")
                          )
                        )
                      })),
                      "×"
                    )
                  )
                )
            )
          ,
          active.map {
            case true =>
              div(
                input.withSelf { self =>
                  (
                    cls := "w-full py-1 px-2 text-sm font-mono rounded bg-glade-green-50 border border-glade-green-200 text-gray-900",
                    onKeyPress --> (_.foreach(evt =>
                      // confirm adding a relay hint
                      evt.key match {
                        case "Enter" =>
                          self.value.get
                          .map{
                            case url if url.isEmpty => url
                            case url if url.contains("://") => url
                            case url if !url.contains("://") && url.nonEmpty => url.prependedAll("wss://")
                            case _ => ""
                          }
                          .flatMap(url =>
                            if url.contains("://")
                            then {
                              store.result.get.flatMap(result =>
                                store.input.set(
                                  result
                                    .map {
                                      case a: AddressPointer =>
                                        NIP19
                                          .encode(
                                            a.copy(relays = a.relays :+ url)
                                          )
                                      case p: ProfilePointer =>
                                        NIP19
                                          .encode(
                                            p.copy(relays = p.relays :+ url)
                                          )
                                      case e: EventPointer =>
                                        NIP19
                                          .encode(
                                            e.copy(relays = e.relays :+ url)
                                          )
                                      case r => ""
                                    }
                                    .getOrElse("")
                                )
                              )
                                >> active.set(false)
                            } else IO.unit
                          )
                        case _ => IO.unit
                      }
                    ))
                  )
                }
              )
            case false if dynamic =>
              // button to add a new relay hint
              button(
                Styles.buttonSmall,
                "add relay hint",
                onClick --> (_.foreach(_ => active.set(true)))
              )
            case false => div("")
          }
        )
      }

  private def selectable(
      store: Store,
      code: String
  ): Resource[IO, HtmlSpanElement[IO]] =
    span(
      store.input.map(current =>
        if current == code then a("")
        else
          a(
            href := "#/" + code,
            onClick --> (_.foreach(evt =>
              evt.preventDefault >>
                store.input.set(code)
            )),
            edit
          )
      )
    )

  private val edit = img(cls := "inline w-4 ml-2", src := "./edit.svg")
  private val external = img(cls := "inline w-4 ml-2", src := "./ext.svg")
}
