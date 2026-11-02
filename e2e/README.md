# End-to-end tests

Due to the nature of the ADSys project, there is only so much validation we can get from unit tests and integration tests. Because these do not interact with a real AD environment, certain scenarios, interactions and edge cases will remain untested.

To bridge this gap we have developed an end-to-end tests pipeline that mimics real-world usage of ADSys as close as possible. To accomplish this we provision disposable Ubuntu VMs on Microsoft Azure which we connect to a real Active Directory domain, exercising ADSys functionality through various triggers like the CLI, systemd or PAM.

The end-to-end pipeline uses a client-server model, where many clients (Ubuntu) connect to a single server (AD controller) to run tests. Because a single server is shared between all clients, great care is taken to ensure AD configurations do not overlap, so that multiple pipelines with various ADSys versions can safely run in parallel.

## How does it work?

The process is automated in GitHub Actions and consists of 2 separate scenarios:
- building VM templates (preparing base images for the Ubuntu clients)
- running the tests (asserting ADSys functionality on VMs created from the templates above)

### Building VM templates

Because Canonical doesn't provide Azure Cloud images for Ubuntu Desktop, we try our best to come up with something that closely resembles a desktop experience. This is simply a case of starting from an [Ubuntu Minimal](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/canonical.0001-com-ubuntu-minimal-jammy?tab=overview) image on which we install `ubuntu-desktop` and other packages required for ADSys policy managers to work.

A [provisioning script](https://github.com/ubuntu/adsys/blob/main/e2e/scripts/provision.sh) is then staged and executed on the VM template which enables various PAM modules and prepares the network configuration.

Before powering off the VM, we stage a [first run](https://github.com/ubuntu/adsys/blob/main/e2e/scripts/first-run.sh) script to be executed via cloud-init on the next boot of the VM. This is mainly responsible for setting a unique hostname to the machine.

The process described above is automated and runs weekly on the [E2E - Build image templates](https://github.com/ubuntu/adsys/actions/workflows/e2e-build-images.yaml) workflow.

### Running the tests

The actual testing workflow consists of the following steps:
- build ADSys as a deb for the target Ubuntu version
- provision a client VM from one of our customized templates
  + join client to the AD domain
  + stage and install the previously built ADSys artifact
- configure the AD domain controller
  + convert GPO data from XML to POL and copy it over
  + create GPOs and OUs unique to the client being tested
  + create AD users unique to the client being tested
- run various test scenarios involving ADSys
- deprovision client VM and clean up AD resources

Because triggering this on every push would be wasteful, the [E2E - Run tests](https://github.com/ubuntu/adsys/actions/workflows/e2e-tests.yaml) workflow only runs on pushes to `main` and on a workflow dispatch basis. We rely on the developer to assess when best to trigger a run of the workflow, as a last action before merging a PR (assuming all other automated checks are passing).

## Developing E2E tests

The end-to-end scenarios are just sequences of Go executables which makes them easy to run locally if needed, either for development or debugging purposes.

### Setting up the VPN

The most painful part of a local setup is configuring the VPN connection required to interact with resources from Azure. The VPN is a SSTP VPN with certificate authentication which is sort of a novelty for Linux-based systems, as support for it was only recently added. We have a bespoke [GitHub action](https://github.com/ubuntu/adsys/blob/main/.github/actions/azure-sstpc-vpn/action.yaml) responsible for setting up the VPN connection, using more recent `sstp-client` and `ppp` packages from a PPA. However, with the release of Ubuntu Noble this might no longer be necessary.

To set up the VPN connection locally refer to the steps in the action linked above, replacing any secret inputs with our own credentials from the Enterprise Desktop LastPass vault.

### Running the E2E scenarios

The scenarios are located in the [e2e/cmd](https://github.com/ubuntu/adsys/tree/main/e2e/cmd) directory, each in its own subdirectory. It's recommended to run the scenarios from the root of the repository using `go run`. The executables are designed to be run in a specific order, as they depend on the state of the AD domain and the client VM. This state is enforced through a shared `inventory.yaml` file which is updated by each scenario.

The following environment variables are required to be present when running the `run_tests` scenario:
- `AD_PASSWORD`: the password for the `localadmin` AD user, used to join the client to the AD domain (available in LastPass)
- `ADSYS_PRO_TOKEN`: Ubuntu Pro token to use on the client VM for testing Pro-only policy managers (you are free to use your own token for development purposes)

Client VMs are accessed through a shared SSH key, so you must have the private key in your `~/.ssh` directory (available in LastPass). The default path is `~/.ssh/adsys-e2e.pem`, but it can be overridden with the `--ssh-key` argument when running the scenarios.

Additionally, you must have the `az` CLI installed and authenticated with access to the Ubuntu Desktop directory. The CLI is used to manage client VMs and create resources in the AD domain.

With everything set up, you can run the scenarios like so:
```sh
go run ./e2e/cmd/run_tests/00_build_adsys_deb -codename jammy
go run ./e2e/cmd/run_tests/01_provision_client
go run ./e2e/cmd/run_tests/02_provision_ad
...
go run ./e2e/cmd/run_tests/99_deprovision
```

For more information refer to the corresponding GitHub Actions workflows responsible for running the scenarios ([e2e-tests.yaml](https://github.com/ubuntu/adsys/blob/main/.github/workflows/e2e-tests.yaml) and [e2e-build-images.yaml](https://github.com/ubuntu/adsys/blob/main/.github/workflows/e2e-build-images.yaml)) and the help messages of the scenarios themselves (run with `-h`).
