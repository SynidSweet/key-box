# Setting up the key box (KBOX-48)

The key box is your Raspberry Pi 3 B+ at home, on the UPS, reached only over your Tailscale network. Nothing here is typed into a command line: each step is a tap, a click, a paste, or reading a screen. The box is opened only from the Pi's own screen, by scanning the square code it shows; this page links to no box address, and you never open one from a message, an email or an agent's note.

Before you start, one rule for the accounts you use here. The Tailscale login and the email behind it are used on your phone and laptop only. One factor that does not sync to any machine the agents use: an **authenticator app synced only to the owner's Google account, which is never signed in on the workstation, devbox or Helsinki**. No passkey sign-in and no SMS on these accounts.

The eight steps, in this order. Agents prepare the pages and files named below; you do the taps.

1. **Laptop, Tailscale admin console.** Open Settings, then Keys, then OAuth clients, then Trust credentials, and delete any entry you did not make. Then look at Users, Device management and DNS. You should see only yourself as a user, and HTTPS and MagicDNS on. If an agent's page says you use a custom policy or Tailnet Lock, follow that page's extra step.
2. **Laptop, Access controls.** Select all, paste the policy file an agent prepared, and Save. The save succeeds.
3. **Laptop, Raspberry Pi Imager.** Device "Raspberry Pi 3", OS "Ubuntu Server 24.04 LTS (64-bit)", your card, **no customisation**, Write. The write finishes and Imager ejects the card.
4. **Laptop, Finder.** Put the card back in. Download `user-data` from the key-box v2 release page, drag it onto the card's `system-boot`, answer Replace, and eject.
5. **At the Pi.** Put in the card, plug in the network cable and the screen, then power the Pi from the UPS. The screen names each stage. Setup can take about 30 minutes, mostly updates, and ends at "scan this code with your phone to add the key box to Tailscale". If the screen ever says "setup was cut off" or "stopped at", write the card again (steps 3 to 5).
6. **Phone.** Scan the square code and tap Connect in Tailscale. If the Machines page asks for approval, tap Approve. The screen moves on to "checking its name" and then "Key box ready".
7. **At the Pi, then phone.** When the screen shows "ready", it also shows 12 words and a second square code. Scan it; on the page that opens, type the 12 words, make the passkey, allow notifications and type a short phrase. If a square code does not draw, type the address shown under it. If the box restarted before this step, the newest words on the screen are the ones that work. The page says the box is set up.
8. **Phone, desk.** Answer the "key box is set up" card, then unplug the screen.

Ubuntu's default package mirrors are plain `http`, which the box's firewall blocks. The bootstrap points apt at an `https` mirror, `https://ports.ubuntu.com/ubuntu-ports`; there is no `http` exemption. These limits do not stop an approved update that is malicious.

Agents then enrol each machine with the box one at a time, and you approve each enrolment on your phone.

## For each Google Cloud project the box makes API keys in (KBOX-59)

Done in the Google Cloud console on your phone, once per project:

1. **A service account named `kbox-keys`** in the project, with the box's workload identity pool principal as Token Creator on it (the box acts as it; there is no downloadable key).
2. **Its roles:** API Keys Admin (makes, lists, reads and deletes keys), Secret Manager Secret Version Adder (only if a key is delivered to a Secret Manager secret there), and Browser (lets it read the project's number, which the box uses to know that an answer names this project).
3. **Two permissions the verifier needs**, `apikeys.keys.lookup` and `resourcemanager.projects.get`: that API Keys Admin and Browser hold them is from Google's documentation and UNVERIFIED (`google.apikey-verify-call`). If a verification answers "unreachable" for every key, check these first.

The APIs `apikeys.googleapis.com`, `cloudresourcemanager.googleapis.com`, `iamcredentials.googleapis.com` and `secretmanager.googleapis.com` must be enabled in the project. A key the box makes there is restricted to the services you approve, and is only ever made in the project you entered with it.

**The box's Google identity (KBOX-41, KBOX-55).** Google cannot reach a box that lives only in your tailnet, so you give Google the box's public keys yourself. The issuer is only a name; nobody fetches it.

1. In the workload identity pool's provider, set the **issuer** to the box's Tailscale name as the box's own page shows it, with `https://` in front. Keep the audience as it is.
2. **First upload of the JWKS.** On your phone, on the box's own page, download the keys file (`/.well-known/jwks.json` on the pages port), then upload it into the provider in the Google Cloud console. Never from a file an agent prepared: an agent's file would let agents act as the box at Google. If the console has no upload field, use the APIs Explorer form for the provider on your phone (UNVERIFIED: U7).
3. If a provider already trusted the old box's name, edit that same provider in this one form. The old box's key stops working when you save.

After that the box uploads each new key itself, one day before it switches.

## Plainly

- The box has one name, its Tailscale name, and it can be reached only from your own tailnet. The Tailscale machine named `keybox` must be free when a new box joins.
- A dead card means a new setup. There is no backup: admin keys are pasted or created again.
- The card is not encrypted. That is why a stolen box has its own runbook below, and why you cut a dead card in two.

## If you lose access

- The app was reinstalled or its data cleared: plug the screen in, restart the box, wait for "Key box ready", and within 30 minutes open `/recover` from the square code (or type the address under it) and type the 12 words.
- The phone is lost: on the new phone, install Tailscale and sign in, remove the lost phone on Tailscale's Machines page, paste and save the policy an agent prepares with the new phone's address, then do the same as for a reinstalled app.
- The key box machine was removed in Tailscale, or the Tailscale login is lost: there is no recovery in the box, so follow "If the card dies".

## If the box is stolen

The thief holds the card, which is not encrypted: it has the vault and the key that encrypts it, the box's signing key, Tailscale's node key and the box's own list of keys. Keys come first, because they work from anywhere at once and are slowest to end. You open no box page during this; agents stop calling the box at step 1. You need no key id: each line of the agents' list names the platform, the project, the key's name and its class. **When unsure, delete it**: every replacement comes through the new box.

1. **Desk:** open the key box card "Report the box stolen" and confirm. It is one choice and no free text. The agents' list appears on the card within minutes.
2. **Each platform on the list, top line first** (Google and master keys first, then admin keys, then project keys), on the platform's own site: delete every admin, master or account-level credential, and every key of the listed projects.
3. **Tailscale admin console (phone or laptop):** Machines, then `keybox`, then **Remove**. The thief's copy of the node key stops working.
4. **Phone:** in Google Password Manager, delete the passkey for the key box, and remove the key box app from the home screen.

Where to look on each platform, from that platform's public documentation, read 2026-11-16. Where the documentation did not say, the row says so; then use the site's own settings search and delete by the kind named.

| Platform | Delete these | Where (read 2026-11-16) |
|---|---|---|
| Google | Disable the box's workload identity pool the agents' list names (this ends the stolen signing key's power; the box's `kbox-wif` and `kbox-keys` service accounts are named with it); delete every API key of the listed projects | IAM and Admin, Workload Identity Pools: open the box's pool and switch its Status toggle to Disabled (Google's docs name this for the pool, which stops every provider in it); APIs and Services, Credentials, for the keys |
| OpenAI | Every admin key (`sk-admin-`) of the organisation; every service-account key of the listed projects | Organization settings, Admin keys; the project's Service accounts. Not confirmed from the public docs (OpenAI's docs refused automated reading) |
| Anthropic | Every admin key; every ordinary API key of the listed workspaces | Claude Console, Settings, Admin keys and Settings, API keys (`platform.claude.com`), the Organization page for an individual account; page paths from the Console, not confirmed in the docs text |
| Stripe | Every restricted key (`rk_live_`); the box holds no secret key | Dashboard, API keys page: the overflow menu of the key in the "Restricted keys" list, then Expire key (Stripe's docs name expire and rotate; there is no separate delete) |
| Supabase | Every personal access token; the API keys of the listed projects | Account preferences, Access Tokens (`supabase.com/dashboard/account/tokens`); the project's Settings, API Keys |
| Vercel | Every project-scoped token of the listed projects; any account-level token the agents name | Account Settings, Tokens (`vercel.com/account/tokens`): delete the token there |
| ElevenLabs | Every service-account API key of the listed service accounts | Workspace settings (profile icon, top right), Service Accounts tab: delete the key |

The agents mark the box retired in mission control at once, so nothing calls it. When you want a new box, they prepare the steps above again; the policy needs no change unless the phone changed.

## If the card dies

You:

1. On the phone, delete the key box passkey and app.
2. Tailscale admin console: Machines, then `keybox`, then **Remove**. The new card is a new node and the name must be free.
3. Do steps 3 to 8 above with a new card.
4. Cut the old card in two before you throw it away. It still holds the vault, unencrypted.

The agents prepare the same list as for a theft, marked "not urgent": the old keys are orphans the dead box can no longer rotate or delete, so each is replaced through the new box and the old one deleted at its service by the same rule as in the table above. Mission control's link to the old box is ended and made again for the new one (the re-link), and it pins the new box's key.
