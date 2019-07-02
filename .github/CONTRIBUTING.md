# How to contribute

The following guidelines for contribution should be followed if you want to submit a pull request.

## How to prepare

* You need a [GitHub account](https://github.com/signup/free)
* Submit an [issue](https://github.com/blowdart/idunno.Authentication/issues) for your issue if there isn't yet.
    * If your issue asks how to harden any of the authentication handlers against hackers it will be closed immediatly. Suggestions for this are in the readme.
* Describe the issue and include steps to reproduce the problem if it's a bug.
* Ensure you mention the earliest version that you know is affected.
* If you are able and want to fix this, fork the repository on GitHub

## Make Changes

* In your forked repository, create a topic branch for your upcoming patch. (e.g. `feature--onlyworkonssl`)
    * Usually this is based on the master branch.
    * Create a branch based on master; avoid working directly on the `master` branch.
* Make sure you stick to the coding style that is used already.
* Make commits of logical units and describe them properly.
* Check for unnecessary whitespace with `git diff --check` before committing.
* If possible, submit tests to your patch / new feature so it can be tested easily.
* Assure nothing is broken by running all the tests. Of course if you want to submit tests that would be just super.

## Submit Changes

* Push your changes to a topic branch in your fork of the repository.
* Open a pull request to the original repository and choose the right original branch you want to patch.
* If not done in commit messages (which you really should do) please reference and update your issue with the code changes. But _please do not close the issue yourself_.

# Additional Resources

* [General GitHub documentation](http://help.github.com/)
* [GitHub pull request documentation](http://help.github.com/send-pull-requests/)
