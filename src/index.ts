import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import { google } from "googleapis";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

const CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar";

type Config = {
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  tokenPath?: string;
  authStatePath?: string;
};

type OAuthState = {
  verifier: string;
  state: string;
  createdAt: string;
  redirectUri: string;
};

const defaultSecrets = path.join(
  os.homedir(),
  ".openclaw",
  "secrets",
);

function paths(config: Config) {
  return {
    token:
      config.tokenPath ??
      path.join(
        defaultSecrets,
        "google-calendar-token.json",
      ),

    authState:
      config.authStatePath ??
      path.join(
        defaultSecrets,
        "google-calendar-auth-state.json",
      ),
  };
}

function clientConfig(config: Config) {
  const clientId =
    config.clientId ??
    process.env.GOOGLE_CALENDAR_CLIENT_ID;

  const clientSecret =
    config.clientSecret ??
    process.env.GOOGLE_CALENDAR_CLIENT_SECRET;

  const redirectUri =
    config.redirectUri ??
    process.env.GOOGLE_CALENDAR_REDIRECT_URI ??
    "http://127.0.0.1:53682/oauth2callback";

  if (!clientId) {
    throw new Error(
      "Google Calendar is not configured. Set clientId in plugin config or GOOGLE_CALENDAR_CLIENT_ID.",
    );
  }

  return {
    clientId,
    clientSecret,
    redirectUri,
  };
}

async function readJson(file: string): Promise<any> {
  return JSON.parse(
    await fs.readFile(file, "utf8"),
  );
}

async function writeSecret(
  file: string,
  value: unknown,
) {
  await fs.mkdir(
    path.dirname(file),
    { recursive: true },
  );

  await fs.writeFile(
    file,
    JSON.stringify(value, null, 2),
    {
      mode: 0o600,
    },
  );

  await fs.chmod(file, 0o600).catch(() => {});
}

function base64Url(buffer: Buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createPkce() {
  const verifier = base64Url(
    crypto.randomBytes(48),
  );

  const challenge = base64Url(
    crypto
      .createHash("sha256")
      .update(verifier)
      .digest(),
  );

  return {
    verifier,
    challenge,
  };
}

async function oauthClient(config: Config) {
  const {
    clientId,
    clientSecret,
    redirectUri,
  } = clientConfig(config);

  return new google.auth.OAuth2(
    clientId,
    clientSecret,
    redirectUri,
  );
}

async function calendarApi(config: Config) {
  const p = paths(config);
  const auth = await oauthClient(config);

  let token: any;

  try {
    token = await readJson(p.token);
  } catch {
    throw new Error(
      "Google Calendar is not authorized. Run google_calendar_auth_start first.",
    );
  }

  if (
    !token?.refresh_token &&
    !token?.access_token
  ) {
    throw new Error(
      "Google Calendar token is invalid. Run google_calendar_auth_start again.",
    );
  }

  auth.setCredentials(token);

  auth.on("tokens", async (tokens) => {
    try {
      const current =
        await readJson(p.token).catch(
          () => ({}),
        );

      await writeSecret(
        p.token,
        {
          ...current,
          ...tokens,
        },
      );
    } catch {
      // Token refresh must not break the API request.
    }
  });

  return google.calendar({
    version: "v3",
    auth,
  });
}

async function buildAuthorizationUrl(
  config: Config,
) {
  const {
    clientId,
    redirectUri,
  } = clientConfig(config);

  const {
    verifier,
    challenge,
  } = createPkce();

  const state = base64Url(
    crypto.randomBytes(32),
  );

  const authState: OAuthState = {
    verifier,
    state,
    createdAt:
      new Date().toISOString(),
    redirectUri,
  };

  await writeSecret(
    paths(config).authState,
    authState,
  );

  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    access_type: "offline",
    prompt: "consent",
    scope: CALENDAR_SCOPE,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  return `https://accounts.google.com/o/oauth2/v2/auth?${query.toString()}`;
}

async function completeAuthorization(
  config: Config,
  input: string,
) {
  const p = paths(config);

  const pending =
    (await readJson(
      p.authState,
    ).catch(() => null)) as OAuthState | null;

  if (
    !pending?.verifier ||
    !pending?.state
  ) {
    throw new Error(
      "No pending Google authorization. Run google_calendar_auth_start first.",
    );
  }

  let code = input.trim();
  let returnedState: string | null = null;

  /*
   * Accept either:
   *
   * 1. Full callback URL
   * 2. Raw authorization code
   */

  if (
    code.startsWith("http://") ||
    code.startsWith("https://")
  ) {
    let url: URL;

    try {
      url = new URL(code);
    } catch {
      throw new Error(
        "The supplied callback URL is invalid.",
      );
    }

    const error =
      url.searchParams.get("error");

    if (error) {
      const description =
        url.searchParams.get(
          "error_description",
        );

      throw new Error(
        `Google OAuth error: ${error}${
          description
            ? ` - ${description}`
            : ""
        }`,
      );
    }

    code =
      url.searchParams.get("code") ?? "";

    returnedState =
      url.searchParams.get("state");
  }

  if (!code) {
    throw new Error(
      "No authorization code found. Paste the full Google callback URL or authorization code.",
    );
  }

  if (
    returnedState &&
    returnedState !== pending.state
  ) {
    throw new Error(
      "OAuth state mismatch. Run google_calendar_auth_start again.",
    );
  }

  const auth =
    await oauthClient(config);

  let tokens;

  try {
    const result =
      await auth.getToken({
        code,
        codeVerifier:
          pending.verifier,
      });

    tokens = result.tokens;
  } catch (error: any) {
    const message =
      error?.response?.data?.error_description ??
      error?.message ??
      "Google OAuth token exchange failed.";

    throw new Error(
      `Google OAuth failed: ${message}`,
    );
  }

  if (
    !tokens.access_token &&
    !tokens.refresh_token
  ) {
    throw new Error(
      "Google did not return a valid OAuth token.",
    );
  }

  await writeSecret(
    p.token,
    tokens,
  );

  await fs.rm(
    p.authState,
    {
      force: true,
    },
  );

  return {
    ok: true,
    message:
      "Google Calendar connected successfully.",
  };
}

function eventView(event: any) {
  return {
    id: event.id,
    status: event.status,
    summary: event.summary,
    description: event.description,
    location: event.location,
    start: event.start,
    end: event.end,
    recurrence: event.recurrence,
    reminders: event.reminders,
    htmlLink: event.htmlLink,
  };
}

export default defineToolPlugin({
  id: "genex-google-calendar",

  name: "Google Calendar",

  description:
    "Manage Google Calendars, events and calendar notifications through Google Calendar API.",

  configSchema: Type.Object({
    clientId: Type.Optional(
      Type.String(),
    ),

    clientSecret: Type.Optional(
      Type.String(),
    ),

    redirectUri: Type.Optional(
      Type.String(),
    ),

    tokenPath: Type.Optional(
      Type.String(),
    ),

    authStatePath: Type.Optional(
      Type.String(),
    ),
  }),

  tools: (tool) => [
    tool({
      name: "google_calendar_auth_start",

      label:
        "Connect Google Calendar",

      description:
        "Start Google Calendar authorization and return one Google authorization link.",

      parameters: Type.Object({}),

      execute: async (
        _params,
        config,
      ) => {
        const authorizationUrl =
          await buildAuthorizationUrl(
            config,
          );

        return {
          ok: true,

          authorizationUrl,

          instructions:
            "Open the Google authorization link, choose the Google account and press Allow. If Google redirects to a callback page, paste the complete callback URL into google_calendar_auth_complete.",
        };
      },
    }),

    tool({
      name: "google_calendar_auth_complete",

      label:
        "Finish Google Calendar Connection",

      description:
        "Finish Google Calendar authorization using the Google callback URL or authorization code.",

      parameters: Type.Object({
        codeOrCallbackUrl:
          Type.String(),
      }),

      execute: async (
        {
          codeOrCallbackUrl,
        },
        config,
      ) =>
        completeAuthorization(
          config,
          codeOrCallbackUrl,
        ),
    }),

    tool({
      name: "google_calendar_auth_status",

      label:
        "Google Calendar Connection Status",

      description:
        "Check whether Google Calendar is connected.",

      parameters: Type.Object({}),

      execute: async (
        _params,
        config,
      ) => {
        const token =
          await readJson(
            paths(config).token,
          ).catch(() => null);

        return {
          connected:
            Boolean(
              token?.refresh_token ||
              token?.access_token,
            ),
        };
      },
    }),

    tool({
      name: "google_calendar_list",

      label: "List Calendars",

      description:
        "List calendars available to the authenticated Google account.",

      parameters: Type.Object({}),

      execute: async (
        _params,
        config,
      ) => {
        const api =
          await calendarApi(config);

        const result =
          await api.calendarList.list({
            maxResults: 250,
          });

        return (
          result.data.items ?? []
        ).map((calendar) => ({
          id: calendar.id,
          name: calendar.summary,
          description:
            calendar.description,
          location:
            calendar.location,
          timeZone:
            calendar.timeZone,
          primary:
            calendar.primary ?? false,
          accessRole:
            calendar.accessRole,
        }));
      },
    }),

    tool({
      name:
        "google_calendar_create_calendar",

      label: "Create Calendar",

      description:
        "Create a new Google Calendar.",

      parameters: Type.Object({
        name: Type.String(),

        description:
          Type.Optional(
            Type.String(),
          ),

        location:
          Type.Optional(
            Type.String(),
          ),

        timeZone:
          Type.Optional(
            Type.String(),
          ),
      }),

      execute: async (
        {
          name,
          description,
          location,
          timeZone,
        },
        config,
      ) => {
        const api =
          await calendarApi(config);

        const result =
          await api.calendars.insert({
            requestBody: {
              summary: name,
              description,
              location,
              timeZone:
                timeZone ??
                "Europe/Paris",
            },
          });

        return {
          ok: true,
          calendar: result.data,
        };
      },
    }),

    tool({
      name:
        "google_calendar_update_calendar",

      label: "Update Calendar",

      description:
        "Update a Google Calendar.",

      parameters: Type.Object({
        calendarId:
          Type.String(),

        name:
          Type.Optional(
            Type.String(),
          ),

        description:
          Type.Optional(
            Type.String(),
          ),

        location:
          Type.Optional(
            Type.String(),
          ),

        timeZone:
          Type.Optional(
            Type.String(),
          ),
      }),

      execute: async (
        {
          calendarId,
          name,
          description,
          location,
          timeZone,
        },
        config,
      ) => {
        const api =
          await calendarApi(config);

        const result =
          await api.calendars.patch({
            calendarId,

            requestBody: {
              ...(name !== undefined
                ? {
                    summary: name,
                  }
                : {}),

              ...(description !==
              undefined
                ? {
                    description,
                  }
                : {}),

              ...(location !== undefined
                ? {
                    location,
                  }
                : {}),

              ...(timeZone !== undefined
                ? {
                    timeZone,
                  }
                : {}),
            },
          });

        return {
          ok: true,
          calendar: result.data,
        };
      },
    }),

    tool({
      name:
        "google_calendar_delete_calendar",

      label: "Delete Calendar",

      description:
        "Delete a non-primary Google Calendar.",

      parameters: Type.Object({
        calendarId:
          Type.String(),
      }),

      execute: async (
        {
          calendarId,
        },
        config,
      ) => {
        if (
          calendarId === "primary"
        ) {
          throw new Error(
            "The primary calendar cannot be deleted.",
          );
        }

        const api =
          await calendarApi(config);

        await api.calendars.delete({
          calendarId,
        });

        return {
          ok: true,
          calendarId,
        };
      },
    }),

    tool({
      name:
        "google_calendar_events",

      label: "List Events",

      description:
        "List events in a Google Calendar for a time range.",

      parameters: Type.Object({
        calendarId:
          Type.Optional(
            Type.String(),
          ),

        timeMin:
          Type.Optional(
            Type.String(),
          ),

        timeMax:
          Type.Optional(
            Type.String(),
          ),

        query:
          Type.Optional(
            Type.String(),
          ),

        maxResults:
          Type.Optional(
            Type.Integer({
              minimum: 1,
              maximum: 2500,
            }),
          ),
      }),

      execute: async (
        {
          calendarId,
          timeMin,
          timeMax,
          query,
          maxResults,
        },
        config,
      ) => {
        const api =
          await calendarApi(config);

        const result =
          await api.events.list({
            calendarId:
              calendarId ??
              "primary",

            timeMin,

            timeMax,

            q: query,

            maxResults:
              maxResults ?? 100,

            singleEvents: true,

            orderBy: "startTime",
          });

        return (
          result.data.items ?? []
        ).map(eventView);
      },
    }),

    tool({
      name:
        "google_calendar_get_event",

      label: "Get Event",

      description:
        "Get one Google Calendar event.",

      parameters: Type.Object({
        calendarId:
          Type.Optional(
            Type.String(),
          ),

        eventId:
          Type.String(),
      }),

      execute: async (
        {
          calendarId,
          eventId,
        },
        config,
      ) => {
        const api =
          await calendarApi(config);

        const result =
          await api.events.get({
            calendarId:
              calendarId ??
              "primary",

            eventId,
          });

        return eventView(
          result.data,
        );
      },
    }),

    tool({
      name:
        "google_calendar_create_event",

      label: "Create Event",

      description:
        "Create a Google Calendar event with optional popup/email reminder and recurrence.",

      parameters: Type.Object({
        calendarId:
          Type.Optional(
            Type.String(),
          ),

        summary:
          Type.String(),

        description:
          Type.Optional(
            Type.String(),
          ),

        location:
          Type.Optional(
            Type.String(),
          ),

        startDateTime:
          Type.Optional(
            Type.String(),
          ),

        endDateTime:
          Type.Optional(
            Type.String(),
          ),

        startDate:
          Type.Optional(
            Type.String(),
          ),

        endDate:
          Type.Optional(
            Type.String(),
          ),

        timeZone:
          Type.Optional(
            Type.String(),
          ),

        reminderMinutes:
          Type.Optional(
            Type.Integer({
              minimum: 0,
              maximum: 40320,
            }),
          ),

        reminderMethod:
          Type.Optional(
            Type.Union([
              Type.Literal("popup"),
              Type.Literal("email"),
            ]),
          ),

        recurrence:
          Type.Optional(
            Type.Array(
              Type.String(),
            ),
          ),
      }),

      execute: async (
        params,
        config,
      ) => {
        const {
          calendarId,
          summary,
          description,
          location,
          startDateTime,
          endDateTime,
          startDate,
          endDate,
          timeZone,
          reminderMinutes,
          reminderMethod,
          recurrence,
        } = params;

        const api =
          await calendarApi(config);

        if (
          startDateTime &&
          !endDateTime
        ) {
          throw new Error(
            "endDateTime is required with startDateTime.",
          );
        }

        if (
          startDate &&
          !endDate
        ) {
          throw new Error(
            "endDate is required with startDate.",
          );
        }

        if (
          !startDateTime &&
          !startDate
        ) {
          throw new Error(
            "Provide startDateTime or startDate.",
          );
        }

        const event: any = {
          summary,
          description,
          location,
          recurrence,
        };

        event.start =
          startDateTime
            ? {
                dateTime:
                  startDateTime,

                ...(timeZone
                  ? {
                      timeZone,
                    }
                  : {}),
              }
            : {
                date: startDate,
              };

        event.end =
          endDateTime
            ? {
                dateTime:
                  endDateTime,

                ...(timeZone
                  ? {
                      timeZone,
                    }
                  : {}),
              }
            : {
                date: endDate,
              };

        if (
          reminderMinutes !==
          undefined
        ) {
          event.reminders = {
            useDefault: false,

            overrides: [
              {
                method:
                  reminderMethod ??
                  "popup",

                minutes:
                  reminderMinutes,
              },
            ],
          };
        }

        const result =
          await api.events.insert({
            calendarId:
              calendarId ??
              "primary",

            requestBody: event,
          });

        return {
          ok: true,
          event: eventView(
            result.data,
          ),
        };
      },
    }),

    tool({
      name:
        "google_calendar_update_event",

      label: "Update Event",

      description:
        "Update an existing Google Calendar event.",

      parameters: Type.Object({
        calendarId:
          Type.Optional(
            Type.String(),
          ),

        eventId:
          Type.String(),

        summary:
          Type.Optional(
            Type.String(),
          ),

        description:
          Type.Optional(
            Type.String(),
          ),

        location:
          Type.Optional(
            Type.String(),
          ),

        startDateTime:
          Type.Optional(
            Type.String(),
          ),

        endDateTime:
          Type.Optional(
            Type.String(),
          ),

        timeZone:
          Type.Optional(
            Type.String(),
          ),

        reminderMinutes:
          Type.Optional(
            Type.Integer({
              minimum: 0,
              maximum: 40320,
            }),
          ),
      }),

      execute: async (
        params,
        config,
      ) => {
        const {
          calendarId,
          eventId,
          summary,
          description,
          location,
          startDateTime,
          endDateTime,
          timeZone,
          reminderMinutes,
        } = params;

        const api =
          await calendarApi(config);

        const body: any = {
          ...(summary !==
          undefined
            ? { summary }
            : {}),

          ...(description !==
          undefined
            ? { description }
            : {}),

          ...(location !==
          undefined
            ? { location }
            : {}),
        };

        if (startDateTime) {
          body.start = {
            dateTime:
              startDateTime,

            ...(timeZone
              ? {
                  timeZone,
                }
              : {}),
          };
        }

        if (endDateTime) {
          body.end = {
            dateTime:
              endDateTime,

            ...(timeZone
              ? {
                  timeZone,
                }
              : {}),
          };
        }

        if (
          reminderMinutes !==
          undefined
        ) {
          body.reminders = {
            useDefault: false,

            overrides: [
              {
                method: "popup",
                minutes:
                  reminderMinutes,
              },
            ],
          };
        }

        const result =
          await api.events.patch({
            calendarId:
              calendarId ??
              "primary",

            eventId,

            requestBody: body,
          });

        return {
          ok: true,
          event: eventView(
            result.data,
          ),
        };
      },
    }),

    tool({
      name:
        "google_calendar_delete_event",

      label: "Delete Event",

      description:
        "Delete a Google Calendar event.",

      parameters: Type.Object({
        calendarId:
          Type.Optional(
            Type.String(),
          ),

        eventId:
          Type.String(),
      }),

      execute: async (
        {
          calendarId,
          eventId,
        },
        config,
      ) => {
        const api =
          await calendarApi(config);

        await api.events.delete({
          calendarId:
            calendarId ??
            "primary",

          eventId,
        });

        return {
          ok: true,
          eventId,
        };
      },
    }),

    tool({
      name:
        "google_calendar_create_reminder",

      label: "Create Reminder",

      description:
        "Create a short Google Calendar event with a popup notification.",

      parameters: Type.Object({
        calendarId:
          Type.Optional(
            Type.String(),
          ),

        title:
          Type.String(),

        dateTime:
          Type.String(),

        durationMinutes:
          Type.Optional(
            Type.Integer({
              minimum: 1,
              maximum: 1440,
            }),
          ),

        reminderMinutesBefore:
          Type.Optional(
            Type.Integer({
              minimum: 0,
              maximum: 40320,
            }),
          ),

        description:
          Type.Optional(
            Type.String(),
          ),
      }),

      execute: async (
        {
          calendarId,
          title,
          dateTime,
          durationMinutes,
          reminderMinutesBefore,
          description,
        },
        config,
      ) => {
        const api =
          await calendarApi(config);

        const start =
          new Date(dateTime);

        if (
          Number.isNaN(
            start.getTime(),
          )
        ) {
          throw new Error(
            `Invalid dateTime: ${dateTime}`,
          );
        }

        const end =
          new Date(
            start.getTime() +
              (durationMinutes ??
                5) *
                60_000,
          );

        const result =
          await api.events.insert({
            calendarId:
              calendarId ??
              "primary",

            requestBody: {
              summary: title,

              description,

              start: {
                dateTime:
                  start.toISOString(),
              },

              end: {
                dateTime:
                  end.toISOString(),
              },

              reminders: {
                useDefault: false,

                overrides: [
                  {
                    method: "popup",

                    minutes:
                      reminderMinutesBefore ??
                      0,
                  },
                ],
              },
            },
          });

        return {
          ok: true,

          event: eventView(
            result.data,
          ),
        };
      },
    }),
  ],
});
