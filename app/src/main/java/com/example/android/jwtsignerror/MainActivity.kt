package com.example.android.jwtsignerror

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.auth.jwt.*
import io.ktor.features.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.serialization.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.serialization.json.Json
import org.slf4j.event.Level
import java.util.*

class MainActivity : AppCompatActivity() {
    private val algorithm = Algorithm.HMAC256("256-bit-secret")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        embeddedServer(Netty, 8000) {
            install(DefaultHeaders)
            install(AutoHeadResponse)
            install(StatusPages)
            install(CallLogging) {
                level = Level.INFO
            }
            install(CORS) {
                anyHost()
            }
            install(ContentNegotiation) {
                json(Json {
                    encodeDefaults = true
                    coerceInputValues = true
                    prettyPrint = true
                    isLenient = true
                })
            }
            install(Authentication) {
                jwt {
                    realm = JWT_REALM
                    verifier(JWT
                            .require(algorithm)
                            .withAudience(JWT_AUDIENCE)
                            .withIssuer(JWT_ISSUER)
                            .build()
                    )

                    validate { credential ->
                        if (credential.payload.getClaim(JWT_CLAIM).asString() == JWT_CLAIM_VALUE) {
                            JWTPrincipal(credential.payload)
                        } else {
                            null
                        }
                    }
                }
            }
            routing {
                get("/") {
                    call.respond(mapOf("Test" to "Hello World"))
                }
                get("/login") {
                    call.respond(generateToken())
                }
                authenticate {
                    get("/protected") {
                        call.respond(mapOf("Ktor JWT" to "Authentication success"))
                    }
                }
            }
        }.start(wait = false)
    }

    private fun generateToken(): String = JWT.create()
            .withSubject("Authentication")
            .withIssuer(JWT_ISSUER)
            .withClaim(JWT_CLAIM, JWT_CLAIM_VALUE)
            .withExpiresAt(Date(System.currentTimeMillis() + JWT_VALIDITY_MS))
            .sign(algorithm)

    companion object {
        private const val JWT_ISSUER = "issuer"
        private const val JWT_AUDIENCE = "audience"
        private const val JWT_REALM = "realm"
        private const val JWT_VALIDITY_MS = 5000L // 5 seconds
        private const val JWT_CLAIM = "claim"
        private const val JWT_CLAIM_VALUE = "value"
    }
}