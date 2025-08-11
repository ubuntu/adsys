(exp::network-proxy)=
# Network proxy

```{include} ../pro_content_notice.txt
    :start-after: <!-- Include start pro -->
    :end-before: <!-- Include end pro -->
```

The proxy manager allows AD administrators to apply proxy settings on the clients. Currently, only system-wide proxy settings are supported.

Proxy settings are configurable under the following GPO path:

* System-wide level, located in `Computer Configuration > Policies > Administrative Templates > Ubuntu > Client management > System proxy configuration`

![System proxy settings in GPO editor](../images/explanation/proxy/system-proxy-settings-list.png)

## Required packages

The [`ubuntu-proxy-manager`](https://github.com/ubuntu/ubuntu-proxy-manager) package must be installed in order for proxy settings to be applied on the client system. On Ubuntu systems, run the following to install the package:

```bash
sudo apt install ubuntu-proxy-manager
```

## Rules precedence

Configured proxy settings will override any settings referenced higher in the GPO hierarchy.

## Setting up the policy

The `System proxy configuration` category provides a list of configurable proxy settings:

* HTTP Proxy
* HTTPS Proxy
* FTP Proxy
* SOCKS Proxy
* Ignored hosts
* Auto configuration URL

![HTTP proxy setting in GPO editor](../images/explanation/proxy/system-proxy-settings-focus.png)

Configured settings will then be forwarded to `ubuntu-proxy-manager` which will apply them on all supported backends (e.g. environment variables, APT, GSettings). For an up-to-date list of supported backends, proxy formats and behaviors, refer to the ubuntu-proxy-manager [documentation](https://github.com/ubuntu/ubuntu-proxy-manager/blob/main/README.md).

### Disabling proxy settings

To disable or remove proxy settings, either set the required values to an empty value (`""`), or mark the setting as `Disabled`.

Note that if none of the proxy settings in the category are set (all settings are `Not Configured`), the proxy manager won't take any action.

## Troubleshooting manager errors

If any proxy GPOs are configured and the `ubuntu-proxy-manager` package is not installed (specifically, no response is received from the D-Bus call on the object exported by the proxy manager service), the manager will fail hard. The package doesn't need to be installed if no proxy entries are configured.

If proxy application fails for other reasons, refer to the [Troubleshooting](https://github.com/ubuntu/ubuntu-proxy-manager/blob/main/README.md#troubleshooting) section of the `ubuntu-proxy-manager` documentation for details on how to debug the D-Bus service.
