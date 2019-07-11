/**
 * SSSD CI.
 *
 * This class hold SSSD CI settings and defines several helper methods
 * that helps reducing code duplication. Unfortunately, it does not
 * seem to be possible to run those methods directly from the pipeline
 * as CI.MethodName() as it produces 'Expected a symbol' error therefore
 * functions outside this class scope must be defined as well. These functions
 * can be then called directly from the pipeline.
 */
class CI {
  /**
   * Absolute path to directory that holds the workspace on Jenkins slave.
   */
  public static String BaseDir = '/home/fedora'

  /**
   * Github status context name that is visible in pull request statuses.
   */
  public static String GHContext = 'sssd-ci'

  /**
   * URL that will be opened when user clicks on 'details' on 'sssd-ci' status.
   */
  public static String GHUrl = 'https://pagure.io/SSSD/sssd'

  /**
   * URL that will be opened when user clicks on 'details' on specific
   * build status (e.g. sssd-ci/fedora28).
   */
  public static String AWS = 'https://s3.eu-central-1.amazonaws.com/sssd-ci'

  /**
   * Path to SSSD Test Suite on Jenkins slave.
   */
  public static String SuiteDir = this.BaseDir + '/sssd-test-suite'

  /**
   * Path to SSSD CI tools on Jenkins slave.
   */
  public static String CIDir = this.BaseDir + '/sssd-ci'

  /**
   * Workaround for https://issues.jenkins-ci.org/browse/JENKINS-39203
   *
   * At this moment if one stage in parallel block fails, failure branch in
   * post block is run in all stages even though they might have been successful.
   *
   * We remember result of test stages in this variable so we can correctly
   * report a success or error even if one of the stages that are run in
   * parallel failed.
   */
  public static def Results = [:]
  public static def RebaseResults = [:]

  /**
   * Mark build as successfull.
   */
  public static def BuildSuccessful(build) {
    this.Results[build] = "success"
  }

  /**
   * Return true if the build was successful.
   */
  public static def IsBuildSuccessful(build) {
    return this.Results[build] == "success"
  }

  /**
   * Mark build as successfully rebased.
   */
  public static def RebaseSuccessful(build) {
    this.RebaseResults[build] = "success"
  }

  /**
   * Return true if the rebase was successful.
   */
  public static def IsRebaseSuccessful(build) {
    return this.RebaseResults[build] == "success"
  }

  /**
   * Send commit status to Github for sssd-ci context.
   */
  public static def Notify(ctx, status, message) {
    ctx.githubNotify status: status,
      context: this.GHContext,
      description: message,
      targetUrl: this.GHUrl
  }

  /**
   * Send commit status to Github for specific build (e.g. sssd-ci/fedora28).
   */
  public static def NotifyBuild(ctx, status, message) {
    ctx.githubNotify status: status,
      context: String.format('%s/%s', this.GHContext, ctx.env.TEST_SYSTEM),
      description: message,
      targetUrl: String.format(
        '%s/%s/%s/%s/index.html',
        this.AWS,
        ctx.env.BRANCH_NAME,
        ctx.env.BUILD_ID,
        ctx.env.TEST_SYSTEM
      )
  }

  public static def Rebase(ctx) {
    if (!ctx.env.CHANGE_TARGET) {
      this.RebaseSuccessful(ctx.env.TEST_SYSTEM)
      return
    }

    ctx.echo String.format('Rebasing on %s', ctx.env.CHANGE_TARGET)

    ctx.sh String.format(
      'git -C %s fetch --no-tags --progress origin +refs/heads/%s:refs/remotes/origin/%s',
      "${ctx.env.WORKSPACE}/sssd",
      ctx.env.CHANGE_TARGET,
      ctx.env.CHANGE_TARGET
    )

    ctx.sh String.format(
      'git -C %s rebase origin/%s',
      "${ctx.env.WORKSPACE}/sssd",
      ctx.env.CHANGE_TARGET
    )

    this.RebaseSuccessful(ctx.env.TEST_SYSTEM)
  }

  /**
   * Run tests. TEST_SYSTEM environment variable must be defined.
   */
  public static def RunTests(ctx) {
    ctx.echo "Running on ${ctx.env.NODE_NAME}"
    this.NotifyBuild(ctx, 'PENDING', 'Build is in progress.')
    this.Rebase(ctx)

    ctx.echo String.format(
      'Executing tests, started at %s',
      (new Date()).format('dd. MM. yyyy HH:mm:ss')
    )

    ctx.sh String.format(
      '%s/sssd-test-suite -c "%s" run --sssd "%s" --artifacts "%s" --update --prune',
      "${this.SuiteDir}",
      "${this.BaseDir}/configs/${ctx.env.TEST_SYSTEM}.json",
      "${ctx.env.WORKSPACE}/sssd",
      "${ctx.env.WORKSPACE}/artifacts/${ctx.env.TEST_SYSTEM}"
    )

    ctx.echo String.format(
      'Finished at %s',
      (new Date()).format('dd. MM. yyyy HH:mm:ss')
    )

    this.BuildSuccessful(ctx.env.TEST_SYSTEM)
  }

  /**
   * Archive artifacts and notify Github about build result.
   */
  public static def WhenCompleted(ctx) {
    if (!this.IsRebaseSuccessful(ctx.env.TEST_SYSTEM)) {
      ctx.echo "Unable to rebase on target branch."
      this.NotifyBuild(ctx, 'FAILURE', 'Unable to rebase on target branch.')
      return
    }

    ctx.archiveArtifacts artifacts: "artifacts/**", allowEmptyArchive: true
    ctx.sh String.format(
      '%s/sssd-ci archive --name "%s" --system "%s" --artifacts "%s"',
      "${this.CIDir}",
      "${ctx.env.BRANCH_NAME}/${ctx.env.BUILD_ID}",
      ctx.env.TEST_SYSTEM,
      "${ctx.env.WORKSPACE}/artifacts/${ctx.env.TEST_SYSTEM}"
    )
    ctx.sh "rm -fr ${ctx.env.WORKSPACE}/artifacts/${ctx.env.TEST_SYSTEM}"

    if (this.IsBuildSuccessful(ctx.env.TEST_SYSTEM)) {
      this.NotifyBuild(ctx, 'SUCCESS', 'Success.')
      return
    }

    this.NotifyBuild(ctx, 'FAILURE', 'Build failed.')
  }

  /**
   * Notify Github that the build was aborted.
   */
  public static def WhenAborted(ctx) {
    this.NotifyBuild(ctx, 'ERROR', 'Aborted.')
  }
}

/**
 * CI class methods cannot be called directly from the pipeline as it
 * yield 'Expected a symbol' error for some reason. This is a workaround
 * for this issue.
 */
def CI_RunTests() { CI.RunTests(this) }
def CI_Post() { CI.WhenCompleted(this) }
def CI_Aborted() { CI.WhenAborted(this) }
def CI_Notify(status, message) { CI.Notify(this, status, message) }

pipeline {
  agent none
  options {
    checkoutToSubdirectory('sssd')
  }
  stages {
    stage('Prepare') {
      steps {
        CI_Notify('PENDING', 'Running tests.')
      }
    }
    stage('Run Tests') {
      parallel {
        stage('Test on Fedora 28') {
          agent {label "sssd-ci"}
          environment { TEST_SYSTEM = "fedora28" }
          steps { CI_RunTests() }
          post {
            always { CI_Post() }
            aborted { CI_Aborted() }
          }
        }
        stage('Test on Fedora 29') {
          agent {label "sssd-ci"}
          environment { TEST_SYSTEM = "fedora29" }
          steps { CI_RunTests() }
          post {
            always { CI_Post() }
            aborted { CI_Aborted() }
          }
        }
        stage('Test on Fedora 30') {
          agent {label "sssd-ci"}
          environment { TEST_SYSTEM = "fedora30" }
          steps { CI_RunTests() }
          post {
            always { CI_Post() }
            aborted { CI_Aborted() }
          }
        }
        stage('Test on Fedora Rawhide') {
          agent {label "sssd-ci"}
          environment { TEST_SYSTEM = "fedora-rawhide" }
          steps { CI_RunTests() }
          post {
            always { CI_Post() }
            aborted { CI_Aborted() }
          }
        }
      }
    }
  }
  post {
    failure {
      CI_Notify('FAILURE', 'Some tests failed.')
    }
    aborted {
      CI_Notify('ERROR', 'Builds were aborted.')
    }
    success {
      CI_Notify('SUCCESS', 'All tests succeeded.')
    }
  }
}
