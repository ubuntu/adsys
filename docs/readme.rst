Documentation starter pack
==========================

See the `Sphinx and Read the Docs <https://canonical-documentation-with-sphinx-and-readthedocscom.readthedocs-hosted.com/>`_ guide for instructions on how to get started with Sphinx documentation.

Then go through the following sections to use this starter pack to set up your docs repository.

Set up your documentation repository
------------------------------------

You can either create a standalone documentation project based on this repository or include the files from this repository in a dedicated documentation folder in an existing code repository.

**Note:** We're planning to provide the contents of this repository as an installable package in the future, but currently, you need to copy and update the required files manually.

Standalone documentation repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To create a standalone documentation repository, clone this starter pack
repository, `update the configuration <#configure-the-documentation>`_, and
then commit all files to the documentation repository.

You don't need to move any files, and you don't need to do any special
configuration on Read the Docs.

Here is one way to do this for newly-created fictional docs repository
``canonical/alpha-docs``:

.. code-block:: none

   git clone git@github.com:canonical/sphinx-docs-starter-pack alpha-docs
   cd alpha-docs
   rm -rf .git
   git init
   git branch -m main
   UPDATE THE CONFIGURATION AND BUILD THE DOCS
   git add -A
   git commit -m "Import sphinx-docs-starter-pack"
   git remote add upstream git@github.com:canonical/alpha-docs
   git push -f upstream main

Documentation in a code repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To add documentation to an existing code repository:

#. create a directory called ``docs`` at the root of the code repository
#. populate the above directory with the contents of the starter pack
   repository (with the exception of the ``.git`` directory)
#. copy the file(s) located in the ``docs/.github/workflows`` directory into
   the code repository's ``.github/workflows`` directory
#. in the above workflow file(s), change the value of the ``working-directory`` field from ``.`` to ``docs``
#. in file ``docs/.readthedocs.yaml`` set the following:

   * ``configuration: docs/conf.py``
   * ``requirements: docs/.sphinx/requirements.txt``

**Note:** When configuring RTD itself for your project, the setting **Path for
.readthedocs.yaml** (under **Advanced Settings**) will need to be given the
value of "docs/.readthedocs.yaml".

Getting started
---------------

There are make targets defined in the ``Makefile`` that do various things. To
get started, we will:

* install prerequisite software
* view the documentation

Install prerequisite software
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the prerequisites:

.. code-block:: none

   make install

This will create a virtual environment (``.sphinx/venv``) and install
dependency software (``.sphinx/requirements.txt``) within it.

A complete set of pinned, known-working dependencies is included in
``.sphinx/pinned-requirements.txt``.

View the documentation
~~~~~~~~~~~~~~~~~~~~~~

To view the documentation:

.. code-block:: none

   make run

This will do several things:

* activate the virtual environment
* build the documentation
* serve the documentation on **127.0.0.1:8000**
* rebuild the documentation each time a file is saved
* send a reload page signal to the browser when the documentation is rebuilt

The ``run`` target is therefore very convenient when preparing to submit a
change to the documentation.

Local checks
~~~~~~~~~~~~

Before committing and pushing changes, it's a good practice to run various checks locally to catch issues early in the development process.

Local build
^^^^^^^^^^^

Run a clean build of the docs to surface any build errors that would occur in RTD:

.. code-block:: none

   make clean-doc
   make html

Spelling check
^^^^^^^^^^^^^^

Ensure there are no spelling errors in the documentation:

.. code-block:: shell

   make spelling

Inclusive language check
^^^^^^^^^^^^^^^^^^^^^^^^

Ensure the documentation uses inclusive language:

.. code-block:: shell

   make woke

Link check
^^^^^^^^^^

Validate links within the documentation:

.. code-block:: shell

   make linkcheck

Configure the documentation
---------------------------

You must modify some of the default configuration to suit your project.
To simplify keeping your documentation in sync with the starter pack, all custom configuration is located in the ``custom_conf.py`` file.
You should never modify the common ``conf.py`` file.

Go through all settings in the ``Project information`` section of the ``custom_conf.py`` file and update them for your project.

See the following sections for further customisation.

Configure the header
~~~~~~~~~~~~~~~~~~~~

By default, the header contains your product tag, product name (taken from the ``project`` setting in the ``custom_conf.py`` file), a link to your product page, and a drop-down menu for "More resources" that contains links to Discourse and GitHub.

You can change any of those links or add further links to the "More resources" drop-down by editing the ``.sphinx/_templates/header.html`` file.
For example, you might want to add links to announcements, tutorials, getting started guides, or videos that are not part of the documentation.

Configure the spelling check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If your documentation uses US English instead of UK English, change this in the
``.sphinx/spellingcheck.yaml`` file.

To add exceptions for words the spelling check marks as wrong even though they are correct, edit the ``.wordlist.txt`` file.

Configure the inclusive-language check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you can't avoid non-inclusive language in some cases, you'll need to
configure exemptions for them.

In-file exemptions
^^^^^^^^^^^^^^^^^^

Suppose a reST file has a link to some site you don't control, and the address
contains "\m\a\s\t\e\r" --- a non-inclusive word. You can't change the link,
but the remainder of the file must be checked for inclusive language. Here the
``woke`` tool's `next-line ignore
<https://docs.getwoke.tech/ignore/#in-line-and-next-line-ignoring>`_ feature is
useful, as follows.

If the link is in-line, move the definition to a line of its own (e.g. among
``.. LINKS`` at the bottom of the file). Above the definition, invoke the
``wokeignore`` rule for the offending word:

.. code-block:: ReST

   .. LINKS
   .. wokeignore:rule=master
   .. _link anchor: https://some-external-site.io/master/some-page.html

Exempt an entire file
^^^^^^^^^^^^^^^^^^^^^

If it's necessary *and safe*, you can exempt a whole file from
inclusive-language checks. To exempt ``docs/foo/bar.rst`` for example, add the
following line to ``.wokeignore``:

.. code-block:: none

   foo/bar.rst

.. note::

   For ``.wokeignore`` to take effect, you must also move it into your
   project's root directory. If you leave it in ``docs/``, the ``woke`` tool
   won't find it and no files will be exempt.

Change checked file-types and locations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, only reST files are checked for inclusive language --- and only
those in ``docs/`` and its subdirectories. To check Markdown files for example,
or files outside the ``docs/`` subtree, you must change how the ``woke`` tool
is invoked.

The ``woke`` command appears twice: in the ``docs/Makefile`` and in your
project's ``.github/workflows/automatic-doc-checks.yml`` file. The command
syntax is out-of-scope here --- consult the `woke User Guide
<https://docs.getwoke.tech/usage/#file-globs>`_.

Configure the link check
~~~~~~~~~~~~~~~~~~~~~~~~

If you have links in the documentation that you don't want to be checked (for
example, because they are local links or give random errors even though they
work), you can add them to the ``linkcheck_ignore`` variable in the ``custom_conf.py`` file.

Activate/deactivate feedback button
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A feedback button is included by default, which appears at the top of each page
in the documentation. It redirects users to your GitHub issues page, and
populates an issue for them with details of the page they were on when they
clicked the button.

If your project does not use GitHub issues, set the ``github_issues`` variable
in the ``custom_conf.py`` file to an empty value to disable both the feedback button
and the issue link in the footer.
If you want to deactivate only the feedback button, but keep the link in the
footer, set ``disable_feedback_button`` in the ``custom_conf.py`` file to ``True``.

Add redirects
~~~~~~~~~~~~~

You can add redirects to make sure existing links and bookmarks continue working when you move files around.
To do so, specify the old and new paths in the ``redirects`` setting of the ``custom_conf.py`` file.

Add custom configuration
~~~~~~~~~~~~~~~~~~~~~~~~

To add custom configurations for your project, see the ``Additions to default configuration`` and ``Additional configuration`` sections in the ``custom_conf.py`` file.
These can be used to extend or override the common configuration, or to define additional configuration that is not covered by the common ``conf.py`` file.

(Optional) Synchronise GitHub issues to Jira
--------------------------------------------

If you wish to sync issues from your documentation repository on GitHub to your
Jira board, configure the `GitHub/Jira sync bot <https://github.com/canonical/gh-jira-sync-bot>`_
by editing the ``.github/workflows/.jira_sync_config.yaml`` file appropriately.
In addition to updating this file, you must also apply server configuration
for this feature to work. For more information, see `server configuration details <https://github.com/canonical/gh-jira-sync-bot#server-configuration>`_
for the GitHub/Jira sync bot.

The ``.jira_sync_config.yaml`` file that is included in the starter pack
contains configuration for syncing issues from the starter pack repository to 
its documentation Jira board.
Therefore, it does not work out of the box for other repositories in GitHub, 
and you must update it if you want to use the synchronisation feature.

Change log
----------

See the `change log <https://github.com/canonical/sphinx-docs-starter-pack/wiki/Change-log>`_ for a list of relevant changes to the starter pack.