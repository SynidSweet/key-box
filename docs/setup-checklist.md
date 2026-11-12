# Setting up the key box (KBOX-48)

Do every step on your phone, in this order. Nothing here is done from the workstation, devbox or Helsinki.

1. **A new email account and a new Oracle account**, each logged into only from the phone.
2. **One factor that does not sync to any machine the agents use:** an **authenticator app synced only to the owner's Google account, which is never signed in on the workstation, devbox or Helsinki**. The passwords for Oracle, deSEC and the email account are not saved anywhere that syncs to those machines. No passkey sign-in and no SMS on these accounts.
3. **Oracle:** pay-as-you-go with a budget alert; the home region near you.
4. **A free `dedyn.io` name** in a deSEC account used only from the phone, with its own login. Turn on DNSSEC if offered.
   - deSEC authenticator app as the second factor: UNVERIFIED.
   - DNSSEC for a `dedyn.io` name: UNVERIFIED.
   - TLS-ALPN-01 for a `dedyn.io` name (how Caddy gets its certificate with port 80 closed): UNVERIFIED.
5. **The instance's public IP** (the one Oracle assigns at creation: it stays while the instance exists, stopped or running, and goes only when the instance is deleted, which means a new setup anyway), with `keys.<domain>` and `api.keys.<domain>` pointing at it.
6. **The instance:** Ubuntu LTS minimal on the A1 shape (1 OCPU, 2 GB), "no SSH key", a public IP assigned at creation, the security list below, and the bootstrap text (`deploy/cloud-init.yaml` at the tagged release) as cloud-init user data. Leave the Compute Instance Monitoring plugin on; turn the Run Command plugin off.
7. **The security list** (egress layer 1, KBOX-46):

   | Direction | Protocol | Address | Port |
   |---|---|---|---|
   | Ingress | TCP | 0.0.0.0/0 | 443 |
   | Egress | TCP | 0.0.0.0/0 | 443 |
   | Egress | UDP | 169.254.169.254/32 | 53 |
   | Egress | TCP | 169.254.169.254/32 | 53 |
   | Egress | UDP | 169.254.169.254/32 | 123 |

   Ubuntu's default mirrors are often plain `http`, which this list blocks. The bootstrap points apt at an `https` mirror; whether one exists for the region is UNVERIFIED and probed on the instance. If none does, security fixes come only through the update unit; there is no `http` exemption.
8. **Read the setup code** in the instance's console history (Oracle console, serial console). It is written there and nowhere else.
9. **Open `https://keys.<domain>/setup`**, type the code, create the passkey and the device key, allow notifications, and type a short phrase.

These limits do not stop an approved update that is malicious.

## Plainly

- The free name can be withdrawn. Then setup is redone on a new name.
- If A1 capacity is unavailable, try again later or another availability domain. The E2.1.Micro shape is not an option: Oracle's idle rule has no memory criterion for it, so it would be reclaimed.

## If you lose access

- The app was reinstalled or its data cleared: recover with the authenticator app on the same phone.
- The phone is lost: recover with the authenticator app restored from your Google account on a new phone.

Both go through `https://keys.<domain>/recover` with the recovery code the box writes to the console at every boot (valid 30 minutes, once). If the web address or the Oracle account is lost, there is no recovery in the box: setup is redone from the bootstrap.
