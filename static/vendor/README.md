# Vendored browser dependencies

Third-party code, shipped unmodified. Nothing in this directory is FFN's; see
[THIRD-PARTY-NOTICES](../../THIRD-PARTY-NOTICES) for the obligations.

The management console loads these from the appliance rather than from a CDN.
That is not a preference. A firewall's management interface must not fetch
executable code from the internet on every page load — it is remote code running
with an administrator's session, and until this change it arrived with no
subresource integrity — and an appliance on an isolated management network,
which is where these are usually deployed, could not fetch it at all: every
chart in the console was blank.

## chart.js 4.4.1 — MIT

`chart.umd.js` is the publisher's own build, taken from the npm package rather
than from a CDN's re-minified copy of it (jsdelivr's `chart.umd.min.js` is 274
bytes different from what the Chart.js project actually published).

    package    https://registry.npmjs.org/chart.js/-/chart.js-4.4.1.tgz
    tarball    sha512-C74QN1bxwV1v2PEujhmKjOZ7iUM4w6BWs23Md/6aOZZSlwMzeCIDGuZay++rBgChYru7/+QFeoQW0fQoP534Dg==
               (the integrity the registry publishes for 4.4.1; verified on download)
    file       package/dist/chart.umd.js -> chart.umd.js
    sha256     74401d738dd3e03ee5dfb3b6841210fe2c4ead8a960c4011ca4ba0b78a9fd8f3
    licence    chart.js-LICENSE.md, from the same package

To re-verify what is committed here, or to move to another version:

```bash
curl -sSLO https://registry.npmjs.org/chart.js/-/chart.js-4.4.1.tgz
openssl dgst -sha512 -binary chart.js-4.4.1.tgz | base64   # compare with the integrity above
tar -xzf chart.js-4.4.1.tgz package/dist/chart.umd.js package/LICENSE.md
sha256sum package/dist/chart.umd.js static/vendor/chart.umd.js
```

The version is pinned deliberately: this change moved *where* the console loads
Chart.js from, and nothing else, so that a chart that renders differently
afterwards has only one possible cause. Upgrading is a separate change with its
own verification — re-run the commands above with the new version, update the
hashes here and the version in `THIRD-PARTY-NOTICES`, and check the console's
charts still draw.
