#!/bin/sh

test_description='git fast index tests'

. ./test-lib.sh

GIT_FASTINDEX_TEST=1; export GIT_FASTINDEX_TEST

test_expect_success 'setup' '
	: >tracked &&
	: >modified &&
	mkdir dir1 &&
	: >dir1/tracked &&
	: >dir1/modified &&
	mkdir dir2 &&
	: >dir2/tracked &&
	: >dir2/modified &&
	git add . &&
	git commit -m initial &&
	cat >.gitignore <<-\EOF
	.gitignore
	expect*
	actual*
	EOF
'

test_expect_success 'fastindex extension is off by default' '
	test_must_fail test-dump-fast-index >actual 2>&1 &&
	grep "^missing or invalid extension" actual
'

test_expect_success 'update-index --fastindex" adds the fsmonitor extension' '
	git update-index --fastindex &&
	test-dump-fast-index >actual &&
	grep "^IEOT with" actual
'

test_expect_success 'update-index --no-fastindex" removes the fastindex extension' '
	git update-index --no-fastindex &&
	test_must_fail test-dump-fast-index >actual &&
	grep "^missing or invalid extension" actual
'

test_expect_success 'verify with and without fastindex returns same result' '
	git update-index --fastindex &&
	test-fast-index
'

test_expect_success 'test with V4 index' '
	git config core.fastindex 1 &&
	git update-index --index-version 4 &&
	test-fast-index
'

test_done
