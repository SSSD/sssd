import hudson.AbortException
import org.jenkinsci.plugins.workflow.steps.FlowInterruptedException

/* Send notifications to Github.
 * If it is an on-demand run then no notifications are sent.
 */
class Notification {
  def pipeline
  String context
  String details_url
  String aws_url
  boolean on_demand

  /* @param pipeline Jenkins pipeline context.
   * @param context Github notification context (the bold text).
   * @param details_url Link for "details" button.
   * @param aws_url Link to cloud where logs are stored.
   * @param on_demand True if this is an on-demand run.
   *
   * There are two types of notifications:
   * a) Summary (i.e. sssd-ci: Success. details: @details_url)
   * b) Single build (i.e. sssd-ci/fedora35: Success. details: @aws_url)
   */
  Notification(pipeline, context, details_url, aws_url, on_demand) {
    this.pipeline = pipeline
    this.context = context
    this.details_url = details_url
    this.aws_url = aws_url
    this.on_demand = on_demand
  }

  /* Send notification. If system is not null single build is notified. */
  def notify(status, message, system = null) {
    def context = system ? "${this.context}/${system}" : this.context
    this.pipeline.echo "[${context}] ${status}: ${message}"

    if (this.on_demand) {
      return
    }

    this.send(status, message, context, this.getTargetURL(system))
  }

  private def send(status, message, context, url) {
    this.pipeline.githubNotify status: status,
      context: context,
      description: message,
      targetUrl: url
  }

  private def getTargetURL(system) {
    if (system) {
      return String.format(
        '%s/%s/%s/%s/index.html',
        this.aws_url,
        this.pipeline.env.BRANCH_NAME,
        this.pipeline.env.BUILD_ID,
        system
      )
    }

    return this.details_url
  }
}

/* Manage test run. */
class Test {
  def pipeline
  String system
  Notification notification

  String artifactsdir
  String basedir
  String codedir
  String target

  /* @param pipeline Jenkins pipeline context.
   * @param system System to test on.
   * @param notification Notification object.
   */
  Test(pipeline, system, notification) {
    this.pipeline = pipeline
    this.system = system
    this.notification = notification

    this.basedir = "/home/fedora"
    this.target = pipeline.env.CHANGE_TARGET
  }

  def handleCmdError(rc) {
    if (rc == 255) {
      this.pipeline.error "Timeout reached."
    } else if (rc != 0) {
      this.pipeline.error "Some tests failed."
    }
  }

  /* Test entry point. */
  def run(command=null) {
    /* These needs to be set here in order to get correct workspace. */
    this.artifactsdir = "${this.pipeline.env.WORKSPACE}/artifacts/${this.system}"
    this.codedir = "${this.pipeline.env.WORKSPACE}/sssd"

    /* Clean-up previous artifacts just to be sure there are no leftovers. */
    this.pipeline.sh "rm -fr ${this.artifactsdir} || :"

    try {
      this.pipeline.echo "Running on ${this.pipeline.env.NODE_NAME}"
      this.notify('PENDING', 'Build is in progress.')
      this.checkout()

      try {
        this.rebase()
      } catch (e) {
        this.pipeline.error "Unable to rebase on ${this.target}."
      }

      this.pipeline.echo "Executing tests, started at ${this.getCurrentTime()}"

      if (command == null) {
        command = String.format(
          '%s/sssd-test-suite -c "%s" run --sssd "%s" --artifacts "%s" --update --prune',
          "${this.basedir}/sssd-test-suite",
          "${this.basedir}/configs/${this.system}.json",
          this.codedir,
          this.artifactsdir
        )
      }

      def rc = this.pipeline.sh script: command, returnStatus: true
      this.handleCmdError(rc)

      this.pipeline.echo "Finished at ${this.getCurrentTime()}"
      this.notify('SUCCESS', 'Success.')
    } catch (FlowInterruptedException e) {
      this.notify('ERROR', 'Aborted.')
      throw e
    } catch (AbortException e) {
      this.notify('ERROR', e.getMessage())
      throw e
    } catch (e) {
      this.notify('ERROR', 'Build failed.')
      throw e
    } finally {
      this.archive()
    }
  }

  def getCurrentTime() {
    def date = new Date()
    return date.format('dd. MM. yyyy HH:mm:ss')
  }

  def checkout() {
    this.pipeline.dir('sssd') {
      this.pipeline.checkout this.pipeline.scm
    }
  }

  def rebase() {
    /* Do not rebase if there is no target (not a pull request). */
    if (!this.target) {
      return
    }

    this.pipeline.echo "Rebasing on ${this.target}"

    // Fetch refs
    this.git(String.format(
      "fetch --no-tags --progress origin +refs/heads/%s:refs/remotes/origin/%s",
      this.target, this.target
    ))

    // Remove left overs from previous rebase if there are any
    this.git("rebase --abort || :")

    // Just to be sure
    this.pipeline.sh "rm -fr '${this.codedir}/.git/rebase-apply' || :"

    // Rebase
    this.git("rebase origin/${this.target}")
  }

  def git(command) {
    this.pipeline.sh "git -C '${this.codedir}' ${command}"
  }

  def archive() {
    this.pipeline.archiveArtifacts artifacts: "artifacts/**",
      allowEmptyArchive: true

    this.pipeline.sh String.format(
      '%s/sssd-ci archive --name "%s" --system "%s" --artifacts "%s"',
      "${this.basedir}/sssd-ci",
      "${pipeline.env.BRANCH_NAME}/${pipeline.env.BUILD_ID}",
      this.system,
      "${artifactsdir}"
    )

    this.pipeline.sh "rm -fr ${this.artifactsdir}"
  }

  def notify(status, message) {
    this.notification.notify(status, message, this.system)
  }
}

/* Manage test run for on demand test. */
class OnDemandTest extends Test {
  String repo
  String branch

  /* @param pipeline Jenkins pipeline context.
   * @param system System to test on.
   * @param notification Notification object.
   * @param repo Repository fetch URL.
   * @param branch Branch to checkout.
   */
  OnDemandTest(pipeline, system, notification, repo, branch) {
    super(pipeline, system, notification)

    this.repo = repo
    this.branch = branch
  }

  def handleCmdError(rc) {
    super.handleCmdError(rc)
  }

  def run() {
    this.pipeline.echo "Repository: ${this.repo}"
    this.pipeline.echo "Branch: ${this.branch}"

    super.run()
  }

  def checkout() {
    this.pipeline.dir('sssd') {
      this.pipeline.git branch: this.branch, url: this.repo
    }
  }

  def rebase() {
    /* Do nothing. */
  }

  def archive() {
    this.pipeline.echo 'On demand run. Artifacts are not stored in the cloud.'
    this.pipeline.echo 'They are accessible only from Jenkins.'
    this.pipeline.echo "${this.pipeline.env.BUILD_URL}/artifact/artifacts/${this.system}"
    this.pipeline.archiveArtifacts artifacts: "artifacts/**",
      allowEmptyArchive: true

    this.pipeline.sh "rm -fr ${this.artifactsdir}"
  }
}

/* Manage test run for internal covscan test.
 * Can be triggered for PRs, ondemand and branch runs */
class Covscan extends Test {
  String repo
  String branch
  String basedir
  String pr_number
  boolean on_demand
  String artifactsdir

  /* @param pipeline Jenkins pipeline context.
   * @param notification Notification object.
   * @param repo Repository fetch URL.
   * @param branch Branch to checkout.
   * @param pr_number Pull Request Number, null if not inside a PR.
   * @param on_demand true for on_demand runs, false otherwise.
   */
  Covscan(pipeline, notification, repo, branch, pr_number, on_demand) {
    super(pipeline, "covscan", notification)

    this.repo = repo
    this.branch = branch
    this.pr_number = pr_number
    this.basedir = "/home/fedora"
    this.on_demand = on_demand
  }

  /* Errors returned from covscan.sh */
  def handleCmdError(rc) {
    if (rc == 0) { return }

    switch (rc) {
      case 1:
        this.pipeline.error "Covscan diff shows new errors!"
        break
      case 2:
        this.pipeline.error "Covscan task FAILED"
        break
      case 3:
        this.pipeline.error "Covscan task INTERRUPTED"
        break
      case 4:
        this.pipeline.error "Covscan task CANCELLED"
        break
      case 255:
        this.pipeline.error "Timeout reached."
        break
      default:
        this.pipeline.error "Generic Failure, unknown return code"
        break
    }
  }

  def run() {
    def version = this.pr_number ? this.pr_number : this.branch.trim()
    this.pipeline.echo "Executing covscan script with version: ${version}_${this.pipeline.env.BUILD_ID}"

    def command = String.format(
      '%s/scripts/covscan.sh "%s%s_%s" "%s"',
      this.basedir,
      this.pr_number ? "pr" : "",
      version,
      this.pipeline.env.BUILD_ID,
      this.pipeline.env.WORKSPACE,
    )

    super.run(command)
  }

  def checkout() {
    if (on_demand) {
      this.pipeline.echo "Checkout ${this.branch}"

      this.pipeline.dir('sssd') {
        this.pipeline.git branch: this.branch, url: this.repo
      }
    } else {
      this.pipeline.dir('sssd') {
        this.pipeline.checkout this.pipeline.scm
      }
    }
  }

  def rebase() {
    super.rebase()
  }

  def archive() {
    if (on_demand) {
      this.pipeline.echo 'On demand run. Artifacts are not stored in the cloud.'
      this.pipeline.echo 'They are accessible only from Jenkins.'
      this.pipeline.echo "${this.pipeline.env.BUILD_URL}/artifact/artifacts/${this.system}"
      this.pipeline.archiveArtifacts artifacts: "artifacts/**",
        allowEmptyArchive: true

      this.pipeline.sh "rm -fr ${this.artifactsdir}"
    } else {
      super.archive()
    }
  }

  def notify(status, message) {
    this.notification.notify(status, message, "covscan")
  }
}

def systems = []
def pr_labels = []
def with_tests_label = false
def with_tests_title = false
def on_demand = params.ON_DEMAND ? true : false
def notification = new Notification(
  this, 'sssd-ci',
  'https://github.com/SSSD/sssd/blob/master/contrib/test-suite/README.md',
  'https://s3.eu-central-1.amazonaws.com/sssd-ci',
  on_demand
)

this.properties([
    buildDiscarder(logRotator(daysToKeepStr: '30', numToKeepStr: '70')),
])

try {
  stage('Get system list') {
    node('master') {
      if (params.SYSTEMS && params.SYSTEMS != 'all') {
        /* This is a parametrized custom build. System list is taken
         * from provided parameter. */
        systems = params.SYSTEMS.split()
      } else {
        /* This is automated build or custom build that requested
         * tests on all systems (i.e. same systems as master branch) */
        def branch = env.CHANGE_TARGET ? env.CHANGE_TARGET : 'master'
        def config = "systems-${branch}"
        echo "Using configuration: ${config}"

        /* Configuration is read from Jenkins-managed configuration file.
         * Path to the configuration is loaded into env.CONFIG_PATH */
        configFileProvider([
          configFile(fileId: config, variable: 'CONFIG_PATH')
        ]) {
          def contents = readFile "${env.CONFIG_PATH}"
          systems = contents.split()
        }
      }

      echo 'Test will be done on following systems:'
      echo systems.join(', ')
    }
  }

  /* Setup nice build description so pull request are easy to find. */
  stage('Setup description') {
    node('master') {
      if (on_demand) {
        /* user: branch */
        def build = currentBuild.rawBuild
        def cause = build.getCause(hudson.model.Cause.UserIdCause.class)
        def user = cause.getUserId()
        currentBuild.description = "${user}: ${params.REPO_BRANCH}"
      } else {
        if (env.CHANGE_TARGET) {
          /* PR XXX: pull request name */
          def title = sh returnStdout: true, script: """
            curl -s https://api.github.com/repos/SSSD/sssd/pulls/${env.CHANGE_ID} | \
            python -c "import sys, json; print(json.load(sys.stdin).get('title'))"
          """
          currentBuild.description = "PR ${env.CHANGE_ID}: ${title}"
          if (title.toLowerCase().contains('tests: ')) {
            with_tests_title = true
          }
        } else {
          /* Branch: name */
          currentBuild.description = "Branch: ${env.BRANCH_NAME}"
        }
      }
    }
  }

  stage('Retrieve labels') {
    node('master') {
      if (env.CHANGE_TARGET) {
        def labels = sh returnStdout: true, script: """
          curl -s https://api.github.com/repos/SSSD/sssd/pulls/${env.CHANGE_ID}
        """
        def props = readJSON text: labels
        props['labels'].each { key, value ->
          pr_labels.add(key['name'])
          if (key['name'] == 'Tests') {
              with_tests_label = true
          }
        }
      }
    }
  }

  stage('Prepare systems') {
    notification.notify('PENDING', 'Pending.')

    /* Notify that all systems are pending. */
    for (system in systems) {
      notification.notify('PENDING', 'Awaiting executor', system)
    }
    if ((with_tests_label == false) && (with_tests_title == false)) {
      notification.notify('PENDING', 'Pending.', "covscan")
    }
  }

  /* Run tests on multiple systems in parallel. */
  stage('Run Tests') {
    def stages = [:]
    for (system in systems) {
      def test = null
      if (!on_demand) {
        test = new Test(this, system, notification)
      } else {
        test = new OnDemandTest(
            this, system, notification,
            params.REPO_URL, params.REPO_BRANCH
        )
      }
      stages.put("${system}", {
        node("sssd-ci") {
          stage("${system}") {
            test.run()
          }
        }
      })
    }

    /* Run covscan against non-test related PRs */
    if ((with_tests_label == false) && (with_tests_title == false)) {
      stages.put("covscan", {
        node("sssd-ci") {
          stage("covscan") {
            covscan = new Covscan(this, notification, params.REPO_URL, params.REPO_BRANCH, env.CHANGE_ID, on_demand)
            covscan.run()
          }
        }
      })
    }

    parallel(stages)
  }
  stage('Report results') {
    notification.notify('SUCCESS', 'All tests succeeded.')
  }
} catch (FlowInterruptedException e) {
  stage('Report results') {
    notification.notify('ERROR', 'Aborted.')
    throw e
  }
} catch (e) {
  stage('Report results') {
    notification.notify('ERROR', 'Some tests failed.')
    throw e
  }
}
