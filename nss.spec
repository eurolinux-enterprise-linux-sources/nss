%global nspr_version 4.21.0
%global nss_util_version 3.44.0
%global nss_softokn_fips_version 3.44.0
%global nss_softokn_version 3.44.0
%global required_softokn_build_version -1
%global nss_version 3.44
%global unsupported_tools_directory %{_libdir}/nss/unsupported-tools
%global allTools "certutil cmsutil crlutil derdump modutil nss-policy-check pk12util pp signtool signver ssltap vfychain vfyserv"

# solution taken from icedtea-web.spec
%define multilib_arches x86_64 ppc64 ia64 s390x sparc64
%ifarch %{multilib_arches}
%define alt_ckbi libnssckbi.so.%{_arch}
%else
%define alt_ckbi libnssckbi.so
%endif

# Disable gtests by default for brew builds, because they don't compile
# with the RHEL 6.x default C++ compiler.
# However, QE would like to execute them in a separate environment
# which can have a newer compiler from devtoolset.
# QE should build this package with: rpmbuild --with gtests
%bcond_with gtests

Summary:          Network Security Services
Name:             nss
Version:          %{nss_version}.0
Release:          7%{?dist}
License:          MPLv2.0
URL:              http://www.mozilla.org/projects/security/pki/nss/
Group:            System Environment/Libraries
Requires:         nspr >= %{nspr_version}
Requires:         nss-util >= %{nss_util_version}
Requires:         nss-softokn%{_isa} >= %{nss_softokn_version}%{required_softokn_build_version}
Requires:         nss-system-init
Requires(post):   %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:    nspr-devel >= %{nspr_version}
BuildRequires:    nss-softokn-devel >= %{nss_softokn_version}%{required_softokn_build_version}
BuildRequires:    nss-util-devel >= %{nss_util_version}
BuildRequires:    sqlite-devel
BuildRequires:    zlib-devel
BuildRequires:    pkgconfig
BuildRequires:    gawk
BuildRequires:    psmisc
BuildRequires:    perl
Conflicts:        curl < 7.19.7-26.el6

Source0:          %{name}-%{nss_version}.tar.gz

Source1:          nss.pc.in
Source2:          nss-config.in
Source3:          blank-cert8.db
Source4:          blank-key3.db
Source5:          blank-secmod.db
Source6:          blank-cert9.db
Source7:          blank-key4.db
Source8:          system-pkcs11.txt
Source9:          setup-nsssysinit.sh
Source10:         PayPalEE.cert
Source12:         %{name}-pem-20140125.tar.bz2
Source17:         TestCA.ca.cert
Source18:         TestUser50.cert
Source19:         TestUser51.cert
Source20:         PayPalRootCA.cert
Source21:         PayPalICA.cert
Source22:         nss-rhel6.config
Source23:         TestOldCA.p12

Patch2:           add-relro-linker-option.patch
Patch3:           renegotiate-transitional.patch
Patch4:           nss-noexecstack.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=402712
Patch6:           nss-enable-pem.patch
# Below reference applies to most pem module related patches
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=617723
Patch16:          nss-539183.patch
# must statically link pem against the freebl in the buildroot
# Needed only when freebl or util on tree has new APIS
Patch25:          nsspem-use-system-freebl.patch
# This patch is currently meant for stable branches
Patch29:          nss-ssl-cbc-random-iv-off-by-default.patch
# TODO: Remove this patch when the ocsp test are fixed
Patch40:          nss-3.14.0.0-disble-ocsp-test.patch
# Fedora / RHEL-only patch, the templates directory was originally introduced to support mod_revocator
# will be needed when we try to build nss as requested on rhbz#689919
Patch47:          utilwrap-include-templates.patch
# TODO remove when we switch to building nss without softoken
Patch49:          nss-skip-bltest-and-fipstest.patch
# This patch uses the gcc-iquote dir option documented at
# http://gcc.gnu.org/onlinedocs/gcc/Directory-Options.html#Directory-Options
# to place the in-tree directories at the head of the list of list of directories
# to be searched for for header files. This ensures a build even when system 
# headers are older. Such is the case when starting an update with API changes or even private export changes.
# Once the buildroot has been bootstrapped the patch may be removed but it doesn't hurt to keep it.
Patch50:          iquote.patch
# As of nss-3.21 we compile NSS with -Werror.
# see https://bugzilla.mozilla.org/show_bug.cgi?id=1182667
# This requires a cleanup of the PEM module as we have it here.
# TODO: submit a patch to the interim nss-pem upstream project
# The submission will be very different from this patch as
# cleanup there is already in progress there.
Patch51: pem-compile-with-Werror.patch
Patch52: Bug-1001841-disable-sslv2-libssl.patch
Patch53: Bug-1001841-disable-sslv2-tests.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=943144
#Patch62: nss-fix-deadlock-squash.patch
# Update certdata.txt to version 2.32
Patch54: nss-rhel-6.10-ca-2.32.patch

# Local patch to be carried forward as we rebase nss
# Reverse the changing of the cipher-orders done upstream
Patch90: keep_old_cipher_suite_order.patch
# Revert upstream change of library's signature algorithm default to SHA256
Patch92: p-1058933-b-reversed.patch
# Revert upstream increase of default key size to 2048 bits for certutil
Patch93: 1129573-certutil-key-size-reversed.patch
Patch94: 1129573-test-certutil-key-size-reversed.patch
# Patch to keep the TLS protocol versions that are enabled by default
Patch98: nss-revert-tls-version-defaults.patch
Patch102: enable-tls-12-by-default.patch
Patch105: nss-prevent-abi-issue.patch
Patch106: nss-tests-prevent-abi-issue.patch
Patch110: nss-sni-c-v-fix.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1280846
Patch201: nss-skip-util-gtest.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=1427481
Patch219: nss-pem-catch-failed-ASN1-decoding-of-RSA-keys.patch
#
# new for 3.44
#
Patch130: nss-reorder-cipher-suites-gtests.patch
# To revert the change in:
# https://bugzilla.mozilla.org/show_bug.cgi?id=1377940
Patch136: nss-sql-default.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1453408
Patch139: nss-modutil-skip-changepw-fips.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1542207
Patch147: nss-dsa-policy.patch
# To revert the change in:
# https://bugzilla.mozilla.org/show_bug.cgi?id=818686
Patch148: nss-sysinit-userdb.patch
# Disable nss-sysinit test which is sorely to test the above change
Patch149: nss-skip-sysinit-gtests.patch
# Enable SSLv2 compatible ClientHello, disabled in the change:
# https://bugzilla.mozilla.org/show_bug.cgi?id=1483128
Patch150: nss-ssl2-compatible-client-hello.patch
# TLS 1.3 currently doesn't work under FIPS mode:
# https://bugzilla.redhat.com/show_bug.cgi?id=1710372
Patch151: nss-skip-tls13-fips-tests.sh
# For backward compatibility: make -V "ssl3:" continue working, while
# the minimum version is clamped to tls1.0
#Patch152: nss-version-range-set.patch
# TLS 1.3 currently doesn't work under FIPS mode:
# https://bugzilla.redhat.com/show_bug.cgi?id=1710372
Patch153: nss-fips-disable-tls13.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1552208
Patch154: nss-disable-pkcs1-sigalgs-tls13.patch
# Upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=1553443
Patch155: nss-post-handshake-auth-with-tickets.patch
# https://bugzilla.mozilla.org/show_bug.cgi?id=1473806
Patch156: nss-fix-public-key-from-priv.patch
Patch157: nss-add-ipsec-usage-to-manpage.patch
# https://bugzilla.mozilla.org/show_bug.cgi?id=1571677
Patch158: nss-fix-pkix-name-constraints-common-name.patch
# Cleanups for the RHEL 6 release: 1) more cipher order changes.
Patch159: nss-3.44-ssl-cleanup-rhel6.patch

# keep rhel6 trust on 1024 certificates
Patch160: nss-rhel6-keep-1024-certs.patch

Patch170: nss-ssl-rhel6-gtests-fix.patch

%description
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

%package tools
Summary:          Tools for the Network Security Services
Group:            System Environment/Base
Requires:         %{name}%{?_isa} = %{version}-%{release}

%description tools
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

Install the nss-tools package if you need command-line tools to
manipulate the NSS certificate and key database.

%package sysinit
Summary:          System NSS Initialization
Group:            System Environment/Base
# providing nss-system-init without version so that it can
# be replaced by a better one, e.g. supplied by the os vendor
Provides:         nss-system-init
Requires:         nss = %{version}-%{release}
Requires(post):   coreutils, sed

%description sysinit
Default Operating System module that manages applications loading
NSS globally on the system. This module loads the system defined
PKCS #11 modules for NSS and chains with other NSS modules to load
any system or user configured modules.

%package devel
Summary:          Development libraries for Network Security Services
Group:            Development/Libraries
Provides:         nss-static = %{version}-%{release}
Requires:         nss = %{version}-%{release}
Requires:         nss-util-devel
Requires:         nss-softokn-devel
Requires:         nspr-devel >= %{nspr_version}
Requires:         pkgconfig
BuildRequires:    xmlto

%description devel
Header and Library files for doing development with Network Security Services.


%package pkcs11-devel
Summary:          Development libraries for PKCS #11 (Cryptoki) using NSS
Group:            Development/Libraries
Provides:         nss-pkcs11-devel-static = %{version}-%{release}
Requires:         nss-devel = %{version}-%{release}
Requires:         nss-softokn-freebl-devel >= %{nss_softokn_fips_version}%{required_softokn_build_version}

%description pkcs11-devel
Library files for developing PKCS #11 modules using basic NSS 
low level services.


%prep
%setup -q -n %{name}-%{nss_version}
%{__cp} %{SOURCE10} -f ./nss/tests/libpkix/certs
%{__cp} %{SOURCE17} -f ./nss/tests/libpkix/certs
%{__cp} %{SOURCE18} -f ./nss/tests/libpkix/certs
%{__cp} %{SOURCE19} -f ./nss/tests/libpkix/certs
%{__cp} %{SOURCE20} -f ./nss/tests/libpkix/certs
%{__cp} %{SOURCE21} -f ./nss/tests/libpkix/certs
%{__cp} %{SOURCE23} -f ./nss/tests/tools
%setup -q -T -D -n %{name}-%{nss_version} -a 12

%patch2 -p0 -b .relro
%patch3 -p0 -b .transitional
# The compiler on ppc/ppc64 builders for RHEL-6 doesn't accept -z as a
# linker option.  Use -Wl,-z instead.
%patch4 -p0 -b .noexecstack
%patch6 -p0 -b .libpem
%patch16 -p0 -b .539183
# link pem against buildroot's freebl, essential when mixing and matching
%patch25 -p0 -b .systemfreebl
# activate for stable and beta branches
%patch29 -p0 -b .cbcrandomivoff
%patch40 -p0 -b .noocsptest
%patch47 -p0 -b .templates
%patch49 -p0 -b .skipthem
%patch50 -p0 -b .iquote
%patch51 -p0 -b .compile_Werror
pushd nss
%patch52 -p0 -b .disableSSL2libssl
%patch53 -p0 -b .disableSSL2tests
popd
# moved patch90 to last position
%patch92 -p0 -b .keep_sha1_default
%patch93 -p0 -b .keep_1024_default
%patch94 -p0 -b .test_keep_1024_default
# attention, reverting patch98
%patch98 -p0 -b .keep_tls_default
%patch102 -p1 -b .1272504
%patch90 -p0 -b .1123092
pushd nss
%patch105 -p1 -b .abi_lib
%patch106 -p1 -b .abi_tests
popd
%patch110 -p0 -b .sni_c_v_fix
%patch201 -p0 -b .skip_util_gtest
%patch219 -p1 -b .pem-decoding
pushd nss
%patch130 -p1 -b .reorder-cipher-suites-gtests
%patch136 -p1 -R -b .sql-default
%patch139 -p1 -b .modutil-skip-changepw-fips
%patch148 -R -p1 -b .sysinit-userdb
%patch147 -p1 -b .dsa-policy
%patch149 -p1 -b .skip-sysinit-gtests
%patch150 -p1 -b .ssl2hello
%patch151 -p1 -b .skip-tls13-fips-mode
#%patch152 -p1 -b .version-range-set
%patch153 -p1 -b .fips-disable-tls13
%patch154 -p1 -b .disable-pkcs1-sigalgs-tls13
%patch155 -p1 -b .post-handshake-auth-with-tickets
popd
%patch156 -p1 -b .pub-priv-mechs
%patch157 -p1 -b .ipsec-usage
pushd nss
%patch158 -p1 -b .pkix-name-constraints-common-name
popd
%patch159 -p1 -b .ssl-cleanup
%patch160 -p1 -b .cert1024
%patch170 -p1 -b .ssl-rhel6-gtests-fix
%patch54 -p1 -b .ca-2.32

# ########################################################
# Higher-level libraries and test tools need access to
# module-private headers from util, freebl, and softoken
# until fixed upstream we must copy some headers locally
#########################################################

pemNeedsFromSoftoken="lowkeyi lowkeyti softoken softoknt"
for file in ${pemNeedsFromSoftoken}; do
    %{__cp} ./nss/lib/softoken/${file}.h ./nss/lib/ckfw/pem/
done

# Copying these header until the upstream bug is accepted
# Upstream https://bugzilla.mozilla.org/show_bug.cgi?id=820207
%{__cp} ./nss/lib/softoken/lowkeyi.h ./nss/cmd/rsaperf
%{__cp} ./nss/lib/softoken/lowkeyti.h ./nss/cmd/rsaperf

# Before removing util directory we must save verref.h
# as it will be needed later during the build phase.
%{__mv} ./nss/lib/util/verref.h ./nss/verref.h

##### Remove util/freebl/softoken and low level tools
######## Remove freebl, softoken and util
%{__rm} -rf ./nss/lib/freebl
%{__rm} -rf ./nss/lib/softoken
%{__rm} -rf ./nss/lib/util
######## Remove nss-softokn test tools as we already ran
# the cipher test suite as part of the nss-softokn build
%{__rm} -rf ./nss/cmd/bltest
%{__rm} -rf ./nss/cmd/fipstest
%{__rm} -rf ./nss/cmd/rsaperf_low

pushd nss/tests/ssl
# Create versions of sslcov.txt and sslstress.txt that disable tests
# for SSL2 and EXPORT ciphers.
cat sslcov.txt| sed -r "s/^([^#].*EXPORT|^[^#].*SSL2)/#disabled \1/" > sslcov.noSSL2orExport.txt
cat sslstress.txt| sed -r "s/^([^#].*EXPORT|^[^#].*SSL2)/#disabled \1/" > sslstress.noSSL2orExport.txt
popd

%build

export NSS_NO_SSL2=1

FREEBL_NO_DEPEND=1
export FREEBL_NO_DEPEND

# Enable compiler optimizations and disable debugging code
BUILD_OPT=1
export BUILD_OPT

# Uncomment to disable optimizations
#RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | sed -e 's/-O2/-O0/g'`
#export RPM_OPT_FLAGS

# Generate symbolic info for debuggers
XCFLAGS=$RPM_OPT_FLAGS

# -Wno-error=unused-result is needed to compile gtests with a newer
# compiler from devtoolset, but it doesn't work with the RHEL 6.x
# default C++ compiler.
%if %{with gtests}
XCFLAGS="$XCFLAGS -Wno-error=unused-result"
%endif

export XCFLAGS

PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export PKG_CONFIG_ALLOW_SYSTEM_LIBS
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS

NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
NSPR_LIB_DIR=%{_libdir}

export NSPR_INCLUDE_DIR
export NSPR_LIB_DIR

export NSSUTIL_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nss-util | sed 's/-I//'`
export NSSUTIL_LIB_DIR=%{_libdir}

export FREEBL_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nss-softokn | sed 's/-I//'`
export FREEBL_LIB_DIR=%{_libdir}
export USE_SYSTEM_FREEBL=1
# TODO choose one or the other style and submit a patch upstream
# wtc has suggested using NSS_USE_SYSTEM_FREEBL
export NSS_USE_SYSTEM_FREEBL=1
# prevents running the sha224 portion of the powerup selftest when testing
#export NO_SHA224_AVAILABLE=1

export FREEBL_LIBS=`/usr/bin/pkg-config --libs nss-softokn`

export SOFTOKEN_LIB_DIR=%{_libdir}
# use the system ones
export USE_SYSTEM_NSSUTIL=1
export USE_SYSTEM_SOFTOKEN=1

# tell the upstream build system what we are doing
export NSS_BUILD_WITHOUT_SOFTOKEN=1

NSS_USE_SYSTEM_SQLITE=1
export NSS_USE_SYSTEM_SQLITE

%if ! %{with gtests}
export NSS_DISABLE_GTESTS=1
%endif

export NSS_ALLOW_SSLKEYLOGFILE=1

%ifarch x86_64 ppc64 ia64 s390x sparc64
USE_64=1
export USE_64
%endif

# uncomment if the iquote patch is activated
export IN_TREE_FREEBL_HEADERS_FIRST=1

##### phase 2: build the rest of nss

export NSS_BLTEST_NOT_AVAILABLE=1

export NSS_FORCE_FIPS=1

%{__make} -C ./nss/coreconf
%{__make} -C ./nss/lib/dbm

# Set the policy file location
# if set NSS will always check for the policy file and load if it exists
export POLICY_FILE="nss-rhel6.config"
# location of the policy file
export POLICY_PATH="/etc/pki/nss-legacy"

# nss/nssinit.c, ssl/sslcon.c, smime/smimeutil.c and ckfw/builtins/binst.c
# need nss/lib/util/verref.h which is which is exported privately,
# copy the one we saved during prep so it they can find it.
%{__mkdir_p} ./dist/private/nss
%{__mv} ./nss/verref.h ./dist/private/nss/verref.h

%{__make} -C ./nss
unset NSS_BLTEST_NOT_AVAILABLE

# build the man pages clean
pushd ./nss
%{__make} clean_docs build_docs
popd

# and copy them to the dist directory for %%install to find them
%{__mkdir_p} ./dist/doc/nroff
%{__cp} ./nss/doc/nroff/* ./dist/doc/nroff

# Set up our package file
# The nspr_version and nss_{util|softokn}_version globals used
# here match the ones nss has for its Requires. 
%{__mkdir_p} ./dist/pkgconfig
%{__cat} %{SOURCE1} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss3,g" \
                          -e "s,%%NSS_VERSION%%,%{version},g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSSUTIL_VERSION%%,%{nss_util_version},g" \
                          -e "s,%%SOFTOKEN_VERSION%%,%{nss_softokn_version},g" > \
                          ./dist/pkgconfig/nss.pc

NSS_VMAJOR=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VMAJOR" | awk '{print $3}'`
NSS_VMINOR=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VMINOR" | awk '{print $3}'`
NSS_VPATCH=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VPATCH" | awk '{print $3}'`

export NSS_VMAJOR
export NSS_VMINOR
export NSS_VPATCH

%{__cat} %{SOURCE2} | sed -e "s,@libdir@,%{_libdir},g" \
                          -e "s,@prefix@,%{_prefix},g" \
                          -e "s,@exec_prefix@,%{_prefix},g" \
                          -e "s,@includedir@,%{_includedir}/nss3,g" \
                          -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                          -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                          -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                          > ./dist/pkgconfig/nss-config

chmod 755 ./dist/pkgconfig/nss-config

%{__cat} %{SOURCE9} > ./dist/pkgconfig/setup-nsssysinit.sh
chmod 755 ./dist/pkgconfig/setup-nsssysinit.sh

%{__cp} ./nss/lib/ckfw/nssck.api ./dist/private/nss/

%check
if [ ${DISABLETEST:-0} -eq 1 ]; then
  echo "testing disabled"
  exit 0
fi

# Begin -- copied from the build section

# inform the ssl test scripts that SSL2 is disabled
export NSS_NO_SSL2=1

FREEBL_NO_DEPEND=1
export FREEBL_NO_DEPEND

BUILD_OPT=1
export BUILD_OPT

%ifarch x86_64 ppc64 ia64 s390x sparc64
USE_64=1
export USE_64
%endif

export NSS_BLTEST_NOT_AVAILABLE=1

export NSS_FORCE_FIPS=1

# needed for the fips manging test
export SOFTOKEN_LIB_DIR=%{_libdir}

# End -- copied from the build section

# This is necessary because the test suite tests algorithms that are
# disabled by the system policy.
export NSS_IGNORE_SYSTEM_POLICY=1

# enable the following line to force a test failure
# find ./nss -name \*.chk | xargs rm -f

# Run test suite.
# In order to support multiple concurrent executions of the test suite
# (caused by concurrent RPM builds) on a single host,
# we'll use a random port. Also, we want to clean up any stuck
# selfserv processes. If process name "selfserv" is used everywhere,
# we can't simply do a "killall selfserv", because it could disturb
# concurrent builds. Therefore we'll do a search and replace and use
# a different process name.
# Using xargs doesn't mix well with spaces in filenames, in order to
# avoid weird quoting we'll require that no spaces are being used.

SPACEISBAD=`find ./nss/tests | grep -c ' '` ||:
if [ $SPACEISBAD -ne 0 ]; then
  echo "error: filenames containing space are not supported (xargs)"
  exit 1
fi
MYRAND=`perl -e 'print 9000 + int rand 1000'`; echo $MYRAND ||:
RANDSERV=selfserv_${MYRAND}; echo $RANDSERV ||:
DISTBINDIR=`ls -d ./dist/*.OBJ/bin`; echo $DISTBINDIR ||:
pushd `pwd`
cd $DISTBINDIR
ln -s selfserv $RANDSERV
popd
# man perlrun, man perlrequick
# replace word-occurrences of selfserv with selfserv_$MYRAND
find ./nss/tests -type f |\
  grep -v "\.db$" |grep -v "\.crl$" | grep -v "\.crt$" |\
  grep -vw CVS  |xargs grep -lw selfserv |\
  xargs -l perl -pi -e "s/\bselfserv\b/$RANDSERV/g" ||:

killall $RANDSERV || :

rm -rf ./tests_results
pushd ./nss/tests/
# all.sh is the test suite script

#  don't need to run all the tests when testing packaging
#  nss_cycles: standard pkix upgradedb sharedb
%if %{with gtests}
%global nss_tests "libpkix cert dbtests tools fips sdr crmf smime ssl merge pkits chains ec gtests ssl_gtests"
%else
%global nss_tests "libpkix cert dbtests tools fips sdr crmf smime ssl merge pkits chains ec"
%endif
#  nss_ssl_tests: crl bypass_normal normal_bypass normal_fips fips_normal iopr
#  nss_ssl_run: cov auth stress

# Uncomment these lines if you need to temporarily
# disable the ssl test suites for faster test builds
# global nss_ssl_tests "normal_fips"
# global nss_ssl_run "cov auth"

HOST=localhost DOMSUF=localdomain PORT=$MYRAND NSS_CYCLES=%{?nss_cycles} NSS_TESTS=%{?nss_tests} NSS_SSL_TESTS=%{?nss_ssl_tests} NSS_SSL_RUN=%{?nss_ssl_run} ./all.sh

popd

# Normally, the grep exit status is 0 if selected lines are found and 1 otherwise,
# Grep exits with status greater than 1 if an error ocurred. 
# If there are test failures we expect TEST_FAILURES > 0 and GREP_EXIT_STATUS = 0, 
# With no test failures we expect TEST_FAILURES = 0 and GREP_EXIT_STATUS = 1, whereas 
# GREP_EXIT_STATUS > 1 would indicate an error in grep such as failure to find the log file.
killall $RANDSERV || :

TEST_FAILURES=$(grep -c -- '- FAILED$' ./tests_results/security/localhost.1/output.log) || GREP_EXIT_STATUS=$?
if [ ${GREP_EXIT_STATUS:-0} -eq 1 ]; then
  echo "okay: test suite detected no failures"
else
  if [ ${GREP_EXIT_STATUS:-0} -eq 0 ]; then
    # while a situation in which grep return status is 0 and it doesn't output
    # anything shouldn't happen, set the default to something that is
    # obviously wrong (-1)
    echo "error: test suite had ${TEST_FAILURES:--1} test failure(s)"
    exit 1
  else
    if [ ${GREP_EXIT_STATUS:-0} -eq 2 ]; then
      echo "error: grep has not found log file"
      exit 1
    else
      echo "error: grep failed with exit code: ${GREP_EXIT_STATUS}"
      exit 1
    fi
  fi
fi
echo "test suite completed"


%install

%{__rm} -rf $RPM_BUILD_ROOT

# There is no make install target so we'll do it ourselves.

%{__mkdir_p} $RPM_BUILD_ROOT/%{_includedir}/nss3
%{__mkdir_p} $RPM_BUILD_ROOT/%{_includedir}/nss3/templates
%{__mkdir_p} $RPM_BUILD_ROOT/%{_bindir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{unsupported_tools_directory}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}/pkgconfig

mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1

touch $RPM_BUILD_ROOT%{_libdir}/libnssckbi.so
%{__install} -p -m 755 dist/*.OBJ/lib/libnssckbi.so $RPM_BUILD_ROOT/%{_libdir}/nss/libnssckbi.so

# Copy the binary libraries we want
for file in libnss3.so libnsspem.so libnsssysinit.so libsmime3.so libssl3.so
do
  %{__install} -p -m 755 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Install the empty NSS db files
# Legacy db
%{__mkdir_p} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb
%{__install} -p -m 644 %{SOURCE3} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert8.db
%{__install} -p -m 644 %{SOURCE4} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key3.db
%{__install} -p -m 644 %{SOURCE5} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/secmod.db
# Shared db
%{__install} -p -m 644 %{SOURCE6} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert9.db
%{__install} -p -m 644 %{SOURCE7} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key4.db
%{__install} -p -m 644 %{SOURCE8} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/pkcs11.txt

# Copy the development libraries we want
for file in libcrmf.a libnssb.a libnssckfw.a
do
  %{__install} -p -m 644 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the binaries we want
for file in certutil cmsutil crlutil modutil nss-policy-check pk12util signtool signver ssltap
do
  %{__install} -p -m 755 dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{_bindir}
done

# Copy the binaries we ship as unsupported
for file in atob btoa derdump listsuites ocspclnt pp selfserv strsclnt symkeyutil tstclnt vfyserv vfychain
do
  %{__install} -p -m 755 dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{unsupported_tools_directory}
done

# Copy the include files we want
for file in dist/public/nss/*.h
do
  %{__install} -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy the template files we want
for file in dist/private/nss/nssck.api
do
  %{__install} -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3/templates
done

# Copy the package configuration files
%{__install} -p -m 644 ./dist/pkgconfig/nss.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss.pc
%{__install} -p -m 755 ./dist/pkgconfig/nss-config $RPM_BUILD_ROOT/%{_bindir}/nss-config
# Copy the pkcs #11 configuration script
%{__install} -p -m 755 ./dist/pkgconfig/setup-nsssysinit.sh $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit.sh

# Copy the man pages for the nss tools
for f in "%{allTools}"; do 
  install -c -m 644 ./dist/doc/nroff/${f}.1 $RPM_BUILD_ROOT%{_mandir}/man1/${f}.1
done

%{__mkdir_p} $RPM_BUILD_ROOT%{_sysconfdir}/pki/nss-legacy
%{__install} -p -m 644 %{SOURCE22} $RPM_BUILD_ROOT%{_sysconfdir}/pki/nss-legacy/nss-rhel6.config


%clean
%{__rm} -rf $RPM_BUILD_ROOT

%triggerpostun -n nss-sysinit -- nss-sysinit < 3.12.8-2
# Reverse unwanted disabling of sysinit by faulty preun sysinit scriplet
# from previous versions of nss.spec
/usr/bin/setup-nsssysinit.sh on

%post
# If we upgrade, and the shared filename is a regular file, then we must
# remove it, before we can install the alternatives symbolic link.
if [ $1 -gt 1 ] ; then
  # when upgrading or downgrading
  if ! test -L %{_libdir}/libnssckbi.so; then
    rm -f %{_libdir}/libnssckbi.so
  fi
fi
# Install the symbolic link
# FYI: Certain other packages use alternatives --set to enforce that the first
# installed package is preferred. We don't do that. Highest priority wins.
%{_sbindir}/update-alternatives --install %{_libdir}/libnssckbi.so \
  %{alt_ckbi} %{_libdir}/nss/libnssckbi.so 10
/sbin/ldconfig

%postun
if [ $1 -eq 0 ] ; then
  # package removal
  %{_sbindir}/update-alternatives --remove %{alt_ckbi} %{_libdir}/nss/libnssckbi.so
else
  # upgrade or downgrade
  # If the new installed package uses a regular file (not a symblic link),
  # then cleanup the alternatives link.
  if ! test -L %{_libdir}/libnssckbi.so; then
    %{_sbindir}/update-alternatives --remove %{alt_ckbi} %{_libdir}/nss/libnssckbi.so
  fi
fi
/sbin/ldconfig


%files
%defattr(-,root,root)
%{_libdir}/libnss3.so
%{_libdir}/libssl3.so
%{_libdir}/libsmime3.so
%ghost %{_libdir}/libnssckbi.so
%{_libdir}/nss/libnssckbi.so
%{_libdir}/libnsspem.so
%dir %{_sysconfdir}/pki/nssdb
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/cert8.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/key3.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/secmod.db
%dir %{_sysconfdir}/pki/nss-legacy
%config(noreplace) %{_sysconfdir}/pki/nss-legacy/nss-rhel6.config

%files sysinit
%defattr(-,root,root)
%{_libdir}/libnsssysinit.so
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/cert9.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/key4.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/pkcs11.txt
%{_bindir}/setup-nsssysinit.sh

%files tools
%defattr(-,root,root)
%{_bindir}/certutil
%{_bindir}/cmsutil
%{_bindir}/crlutil
%{_bindir}/modutil
%{_bindir}/nss-policy-check
%{_bindir}/pk12util
%{_bindir}/signtool
%{_bindir}/signver
%{_bindir}/ssltap
%{unsupported_tools_directory}/atob
%{unsupported_tools_directory}/btoa
%{unsupported_tools_directory}/derdump
%{unsupported_tools_directory}/listsuites
%{unsupported_tools_directory}/ocspclnt
%{unsupported_tools_directory}/pp
%{unsupported_tools_directory}/selfserv
%{unsupported_tools_directory}/strsclnt
%{unsupported_tools_directory}/symkeyutil
%{unsupported_tools_directory}/tstclnt
%{unsupported_tools_directory}/vfyserv
%{unsupported_tools_directory}/vfychain
# instead of %%{_mandir}/man*/* let's list them explicitely
# supported tools
%attr(0644,root,root) %doc /usr/share/man/man1/certutil.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/cmsutil.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/crlutil.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/modutil.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/nss-policy-check.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/pk12util.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/signtool.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/signver.1.gz
# unsupported tools
%attr(0644,root,root) %doc /usr/share/man/man1/derdump.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/pp.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/ssltap.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/vfychain.1.gz
%attr(0644,root,root) %doc /usr/share/man/man1/vfyserv.1.gz

%files devel
%defattr(-,root,root)
%{_libdir}/libcrmf.a
%{_libdir}/pkgconfig/nss.pc
%{_bindir}/nss-config

%dir %{_includedir}/nss3
%{_includedir}/nss3/cert.h
%{_includedir}/nss3/certdb.h
%{_includedir}/nss3/certt.h
%{_includedir}/nss3/cmmf.h
%{_includedir}/nss3/cmmft.h
%{_includedir}/nss3/cms.h
%{_includedir}/nss3/cmsreclist.h
%{_includedir}/nss3/cmst.h
%{_includedir}/nss3/crmf.h
%{_includedir}/nss3/crmft.h
%{_includedir}/nss3/cryptohi.h
%{_includedir}/nss3/cryptoht.h
%{_includedir}/nss3/sechash.h
%{_includedir}/nss3/jar-ds.h
%{_includedir}/nss3/jar.h
%{_includedir}/nss3/jarfile.h
%{_includedir}/nss3/key.h
%{_includedir}/nss3/keyhi.h
%{_includedir}/nss3/keyt.h
%{_includedir}/nss3/keythi.h
%{_includedir}/nss3/nss.h
%{_includedir}/nss3/nssckbi.h
%{_includedir}/nss3/nsspem.h
%{_includedir}/nss3/ocsp.h
%{_includedir}/nss3/ocspt.h
%{_includedir}/nss3/p12.h
%{_includedir}/nss3/p12plcy.h
%{_includedir}/nss3/p12t.h
%{_includedir}/nss3/pk11func.h
%{_includedir}/nss3/pk11pqg.h
%{_includedir}/nss3/pk11priv.h
%{_includedir}/nss3/pk11pub.h
%{_includedir}/nss3/pk11sdr.h
%{_includedir}/nss3/pkcs12.h
%{_includedir}/nss3/pkcs12t.h
%{_includedir}/nss3/pkcs7t.h
%{_includedir}/nss3/preenc.h
%{_includedir}/nss3/secmime.h
%{_includedir}/nss3/secmod.h
%{_includedir}/nss3/secmodt.h
%{_includedir}/nss3/secpkcs5.h
%{_includedir}/nss3/secpkcs7.h
%{_includedir}/nss3/smime.h
%{_includedir}/nss3/ssl.h
%{_includedir}/nss3/sslerr.h
%{_includedir}/nss3/sslproto.h
%{_includedir}/nss3/sslt.h
%{_includedir}/nss3/sslexp.h


%files pkcs11-devel
%defattr(-, root, root)
%{_includedir}/nss3/nssbase.h
%{_includedir}/nss3/nssbaset.h
%{_includedir}/nss3/nssckepv.h
%{_includedir}/nss3/nssckft.h
%{_includedir}/nss3/nssckfw.h
%{_includedir}/nss3/nssckfwc.h
%{_includedir}/nss3/nssckfwt.h
%{_includedir}/nss3/nssckg.h
%{_includedir}/nss3/nssckmdt.h
%{_includedir}/nss3/nssckt.h
%{_includedir}/nss3/templates/nssck.api
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a


%changelog
*Wed Oct 23 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-7
- Add back missing Mozilla Policy

* Tue Oct 15 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-6
- Fix gtest failure detection

* Tue Oct 15 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-5
- Turn off cp TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 by default

* Fri Oct 11 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-4
- Fix cipher order
- fix broken gtests

* Tue Oct 8 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-3
- fix problems found by qe:
- AC13: SSL3 "disabled"
- AC26: Chacha20 and TLS 1.3 ciphers should be prioritized
-   SHA-384 PRF => *_256_GCM_SHA384 ciphers should be reenabled for consistency
- AC28: nss-policy-check is missing from packages and $PATH
- extra: apostrophes in certutil manpage got mangled

* Mon Aug 26 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-2
- restore Conflicts: with curl

* Mon Aug 26 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-1
- Rebase to 3.44.0 with critical fixes

* Tue Aug 28 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-9
- Backport upstream fix for CVE-2018-12384
- Remove nss-lockcert-api-change.patch, which turned out to be a
  mistake (the symbol was not exported from libnss)

* Wed Apr 18 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-8
- Restore CERT_LockCertTrust and CERT_UnlockCertTrust back in cert.h

* Thu Mar 29 2018 Kai Engert <kaie@redhat.com> - 3.36.0-7
- rebuild

* Wed Mar 28 2018 Kai Engert <kaie@redhat.com> - 3.36.0-6
- Keep legacy code signing trust flags for backwards compatibility

* Tue Mar 27 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-5
- Decrease the iteration count of PKCS#12 for compatibility with Windows
- Fix deadlock when a token is re-inserted while a client process is running

* Thu Mar 22 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-4
- Ignore tests which only works with newer nss-softokn

* Mon Mar 19 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-3
- Use the correct tarball of NSS 3.36 release
- Ignore EncryptDeriveTest which only works with newer nss-softokn

* Thu Mar 15 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-2
- Don't skip non-FIPS and ECC test cases in ssl.sh

* Thu Mar  8 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-1
- Rebase to NSS 3.36.0

* Wed Feb 28 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-0.1.beta
- Rebase to NSS 3.36.0 BETA
- Remove upstreamed nss-is-token-present-race.patch
- Revert the upstream changes that default to sql database

* Fri Feb 16 2018 Daiki Ueno <dueno@redhat.com> - 3.34.0-3
- Replace race.patch and nss-3.16-token-init-race.patch with
  a proper upstream fix

* Thu Dec  7 2017 Daiki Ueno <dueno@redhat.com> - 3.34.0-2
- Don't restrict nss_cycles to sharedb

* Mon Dec  4 2017 Daiki Ueno <dueno@redhat.com> - 3.34.0-1
- Rebase to NSS 3.34.0

* Mon May 15 2017 Daiki Ueno <dueno@redhat.com> - 3.28.4-3
- Fix zero-length record treatment for stream ciphers and SSLv2

* Fri May  5 2017 Kai Engert <kaie@redhat.com> - 3.28.4-2
- Include CKBI 2.14 and updated CA constraints from NSS 3.28.5

* Fri Apr  7 2017 Daiki Ueno <dueno@redhat.com> - 3.28.4-1
- Rebase to 3.28.4

* Fri Mar 24 2017 Daiki Ueno <dueno@redhat.com> - 3.28.3-3
- Fix crash with tstclnt -W
- Adjust gtests to run with our old softoken and downstream patches

* Wed Mar 15 2017 Daiki Ueno <dueno@redhat.com> - 3.28.3-2
- Avoid cipher suite ordering change, spotted by Hubert Kario

* Tue Feb 28 2017 Daiki Ueno <dueno@redhat.com> - 3.28.3-1
- Rebase to 3.28.3
- Remove upstreamed moz-1282627-rh-1294606.patch,
  moz-1312141-rh-1387811.patch, moz-1315936.patch, and
  moz-1318561.patch
- Remove no longer necessary nss-duplicate-ciphers.patch
- Disable X25519 and exclude tests using it
- Catch failed ASN1 decoding of RSA keys, by Kamil Dudka (#1427481)

* Mon Jan  9 2017 Daiki Ueno <dueno@redhat.com> - 3.27.1-13
- Update expired PayPalEE.cert

* Tue Dec 13 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-12
- Disable unsupported test cases in ssl_gtests

* Tue Dec  6 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-11
- Adjust the sslstress.txt filename so that it matches with the
  disableSSL2tests patch ported from RHEL 7
- Exclude SHA384 and CHACHA20_POLY1305 ciphersuites from stress tests
- Don't add gtests and ssl_gtests to nss_tests, unless gtests are enabled

* Fri Dec  2 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-10
- Add patch to fix SSL CA name leaks, taken from NSS 3.27.2 release
- Add patch to fix bash syntax error in tests/ssl.sh
- Add patch to remove duplicate ciphersuites entries in sslinfo.c
- Add patch to abort selfserv/strsclnt/tstclnt on non-parsable version range
- Build with support for SSLKEYLOGFILE

* Wed Nov 16 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-9
- Update fix_multiple_open patch to fix regression in openldap client
- Remove pk11_genobj_leak patch, which caused crash with Firefox
- Add comment in the policy file to preserve the last empty line
- Disable SHA384 ciphersuites when CKM_TLS12_KEY_AND_MAC_DERIVE is not
  provided by softoken; this superseds check_hash_impl patch

* Fri Nov 11 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-8
- Fix problem in check_hash_impl patch

* Wed Nov  9 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-7
- Add patch to check if hash algorithms are backed by a token
- Add patch to disable TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_CBC_SHA256,
  which have never enabled in the past

* Tue Nov 08 2016 Kai Engert <kaie@redhat.com> - 3.27.1-6
- Add upstream patch to fix a crash. Mozilla #1315936

* Wed Nov 02 2016 Kai Engert <kaie@redhat.com> - 3.27.1-5
- Disable the use of RSA-PSS with SSL/TLS. #1390161

* Mon Oct 31 2016 Kai Engert <kaie@redhat.com> - 3.27.1-4
- Use updated upstream patch for RH bug 1387811

* Thu Oct 27 2016 Kai Engert <kaie@redhat.com> - 3.27.1-3
- Added upstream patches to fix RH bugs 1057388, 1294606, 1387811

* Wed Oct 12 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-2
- Enable gtests when requested

* Tue Oct 11 2016 Daiki Ueno <dueno@redhat.com> - 3.27.1-1
- Rebase to NSS 3.27.1
- Remove nss-646045.patch, which is not necessary
- Remove p-disable-md5-590364-reversed.patch,
  which is no-op here, because the patched code is removed later in
  %%setup
- Remove disable_hw_gcm.patch, which is no-op here, because the
  patched code is removed later in %%setup.  Also remove
  NSS_DISABLE_HW_GCM setting, which was only required for RHEL 5
- Add Bug-1001841-disable-sslv2-libssl.patch and
  Bug-1001841-disable-sslv2-tests.patch, which completedly disable
  EXPORT ciphersuites.  Ported from RHEL 7
- Remove disable-export-suites-tests.patch, which is covered by
  Bug-1001841-disable-sslv2-tests.patch
- Remove nss-ca-2.6-enable-legacy.patch, as we decided to not allow
  1024 legacy CA certificates
- Remove ssl-server-min-key-sizes.patch, as we decided to support DH
  key size greater than 1023 bits
- Remove nss-init-ss-sec-certs-null.patch, which appears to be no-op,
  as it clears memory area allocated with PORT_ZAlloc()
- Remove nss-disable-sslv2-libssl.patch,
  nss-disable-sslv2-tests.patch, sslauth-no-v2.patch, and
  nss-sslstress-txt-ssl3-lower-value-in-range.patch as SSLv2 is
  already disabled in upstream
- Remove fix-nss-test-filtering.patch, which is fixed in upstream
- Add nss-check-policy-file.patch from Fedora
- Install policy config in /etc/pki/nss-legacy/nss-rhel6.config

* Tue Mar 22 2016 Kai Engert <kaie@redhat.com> - 3.21.0-8
- Ensure all ssl.sh tests are executed

* Mon Mar 21 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-7
- Update sslauth patch to run more tests

* Wed Mar 16 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-6
- Fix syntax errors in patch that disables sslv2 tests
- Resolves: Bug 1297888 - Rebase RHEL 6.8 to NSS 3.21 for Firefox 45

* Wed Mar 02 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-5
- Resolves: Bug 1304812 - Disable support for SSLv2 completely.

* Wed Feb 24 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-4
- Add patches for ABI compatibility

* Mon Jan 25 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-3
- Disable extended master-secret due to older version of softoken

* Sat Jan 23 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-2
- Enable two additional ciphers and keep another one disabled
- Prevent enabling extended masker key derive

* Tue Jan 12 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-1
- Rebase to NSS-3.21

* Tue Dec 22 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.1-9
- Prevent TLS 1.2 Transcript Collision attacks against MD5 in key exchange protocol
- Resolves: Bug 1289890

* Thu Nov 19 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.1-7
- Package listsuites as part of the unsupported tools set
- Resolves:  Bug 1283655

* Wed Nov 18 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.1-6
- Resolves: Bug 1272504 - Enable TLS 1.2 as the default in nss 

* Wed Oct 21 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.1-5
- Rebuild against updated NSPR

* Thu Jun 25 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.1-4
- Sync up with the rhel-6.6 branch
- Resolves: Bug 1224450

* Sat Jun 13 2015 Kai Engert <kaie@redhat.com> - 3.19.1-3
- Additional NULL initialization.

* Fri Jun 12 2015 Kai Engert <kaie@redhat.com> - 3.19.1-2
- Updated the patch to keep old cipher suite order
- Resolves: Bug 1224450

* Sat Jun 06 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.1-1
- Rebase to nss-3.19.1
- Resolves: Bug 1224450

* Wed Apr 29 2015 Kai Engert <kaie@redhat.com> - 3.18.0-5.3
- On RHEL 6.x keep the TLS version defaults unchanged.
- Require softokn build 22 to ensure runtime compatibility.
- Relax the requirement from pkcs11-devel to nss-softokn-freebl-devel
  to allow same or newer.
- Update to CKBI 2.4 from NSS 3.18.1 (the only change in NSS 3.18.1)

* Sat Apr 18 2015 Elio Maldonado <emaldona@redhat.com> - 3.18.0-5
- Update and reeneable nss-646045.patch on account of the rebase
- Resolves: Bug 1200900 - Rebase nss to 3.18 for Firefox 38 ESR [RHEL7.1]

* Mon Apr 13 2015 Elio Maldonado <emaldona@redhat.com> - 3.18.0-4
- Fix shell syntax error in nss/tests/all.sh
- Resolves: Bug 1200900 - Rebase nss to 3.18 for Firefox 38 ESR [RHEL-6.6]

* Sat Apr 11 2015 Elio Maldonado <emaldona@redhat.com> - 3.18.0-3
- Restore a patch that had been mistakenly disabled
- Resolves: Bug 1200900 - Rebase nss to 3.18 for Firefox 38 ESR [RHEL-6.6]

* Fri Apr 10 2015 Elio Maldonado <emaldona@redhat.com> - 3.18.0-2
- Replace expired PayPal test certificate that breaks the build
- Resolves: Bug 1200900 - Rebase nss to 3.18 for Firefox 38 ESR [RHEL-6.6]

* Mon Apr 06 2015 Elio Maldonado <emaldona@redhat.com> - 3.18.0-1
- Resolves: Bug 1200900 - Rebase nss to 3.18 for Firefox 38 ESR [RHEL-6.6]
- Resolves: Bug 1131311 - rhel65 ns-slapd crash, segfault error 4 in libnss3.so in PK11_DoesMechanism at pk11slot.c:1824
- Temporarily disable some tests until expired PayPalEE.cert is renewed

* Fri Mar 13 2015 Elio Maldonado <emaldona@redhat.com> - 3.16.2.3-4
- Keep the same cipher suite order as we had in NSS_3_15_3_RTM
- Resolves: Bug 1123092 - openldap-2.4.23-34.el6_5.1.i686 fails after updating nss to nss-3.16.1-4.el6_5.i686

* Wed Nov 26 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.2.3-3
- Resolves: Bug 1158160 - Upgrade to NSS 3.16.2.3 for Firefox 31.3
- Remove unused indentation pseudo patch
- require nss util 3.16.2.3
- Restore patch for certutil man page
- supply missing options descriptions to the man page

* Thu Nov 13 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.2.3-1
- Resolves: Bug 1158160 - Upgrade to NSS 3.16.2.3 for Firefox 31.3

* Wed Sep 24 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-14
- Resolves: Bug 1145432 - CVE-2014-1568

* Wed Aug 20 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-13
- Fix pem deadlock caused by previous version of a fix for a race condition
- Fixes: Bug 1090681

* Fri Aug 15 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-12
- Add references to bugs filed upstream
- Related: Bug 1090681, Bug 1104300

* Mon Aug 11 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-11
- Resolves: Bug 1090681 - RHDS 9.1 389-ds-base-1.2.11.15-31 crash in PK11_DoesMechanism

* Tue Jul 29 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-10
- Replace expired PayPal test certificate that breaks the build
- Related: Bug 1099619

* Mon Jul 21 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-9
- Fix defects found by coverity
- Resolves: Bug 1104300

* Mon Jun 30 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-8
- Backport nss-3.12.6 upstream fix required by Firefox 31
- Resolves: Bug 1099619

* Wed Jun 18 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-7
- Update nspr-version to 4.10.6

* Tue Jun 17 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-6
- Update pem sources to the same ones used on rhel-7
- Remove no longer needed patches on account of this update
- Resolves: Bug 1002205

* Tue Jun 10 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-5
- Move removal of directories to the end of the %%prep section
- Resolves: Bug 689919 - build without any softoken or util sources in the tree

* Fri Jun 06 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-4
- Remove unused patches rendered obsolete

* Fri Jun 06 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-3
- Fix pem module trashing of private keys on failed login
- Resolves: Bug 1002205 - PEM module trashes private keys if login fails

* Thu May 29 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-2
- Restore use of indentation patch until another bug is resolved
- Resolves: Bug 606022 - nss security tools lack man pages

* Wed May 28 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-1
- Update to nss-3.16.1
- Resolves: Bug 1099619 - Rebase nss in RHEL 6.6 to NSS 3.16.1

* Mon Apr 21 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-11
- Resolves: Bug 689919 - build without any softoken or util sources in the tree
- Add define-uint32.patch to deal with using older version of nss-softokn
- Fix suboptimal test failure detection shell code in the %%check section

* Thu Apr 10 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-10
- Prevent users from disabling the internal crypto module
- Resolves: Bug 1059176 - nss segfaults with opencryptoki module

* Wed Mar 26 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-9
- Improve support for ECDSA algorithm via pluggable ECC
- Document the purpose of the iquote.patch
- Resolves: Bug 1057224 - Pluggable ECC in NSS not enabled on RHEL 6 and above

* Wed Mar 26 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-8
- Install man pages for the nss security tools
- Resolves: Bug 606022 - nss security tools lack man pages

* Wed Feb 12 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-7
- Fix the numbering and naming of the patches
- Resolves: Bug 895339 - [PEM] active FTPS with encrypted client key ends up with SSL_ERROR_TOKEN_INSERTION_REMOVAL 

* Wed Jan 22 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-6
- make derEncodingsMatch work with encrypted keys
- rename a patch, dropped the experimental moniker from it
- Resolves: Bug 895339 - [PEM] active FTPS with encrypted client key ends up with SSL_ERROR_TOKEN_INSERTION_REMOVAL 

* Fri Jan 03 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.3-5
- Resolves: Bug 895339 - [PEM] active FTPS with encrypted client key ends up with SSL_ERROR_TOKEN_INSERTION_REMOVAL 

* Fri Dec 13 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3-4
- Revoke trust in one mis-issued anssi certificate
- Resolves: Bug 1042686 - nss: Mis-issued ANSSI/DCSSI certificate (MFSA 2013-117) [rhel-6.6]

* Sun Dec 01 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3-3
- Disable hw gcm on rhel-5 based build environments where OS lacks support
- Rollback changes to build nss without softokn until Bug 689919 is approved
- Cipher suite was run as part of the nss-softokn build

* Fri Nov 29 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3-2
- Build nss without softoken, freebl, or util sources in the build source tree
- Resolves: Bug 1032472 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741

* Mon Nov 25 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3-1
- Update to NSS_3_15_3_RTM
- Resolves: Bug 1032472 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741
- Resolves: Bug 1031238 - deadlock in trust domain lock and object lock

* Tue Oct 15 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-15
- Using export NSS_DISABLE_HW_GCM=1 to deal with some problemmatic build systems
- Resolves: rhbz#1016044 - nss.s390: primary link for libnssckbi.so must be /usr/lib64/libnssckbi.so

* Tue Oct 15 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-14
- Add s390x and ia64 to the %%define multilib_arches list used for defining alt_ckbi
- Resolves: rhbz#1016044 - nss.s390: primary link for libnssckbi.so must be /usr/lib64/libnssckbi.so


* Mon Oct 07 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-13
- Add zero default value to DISABLETEST check and fix the TEST_FAILURES check and reporting
- Resolves: rhbz#990631 - file permissions of pkcs11.txt/secmod.db must be kept when modified by NSS
- Related: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x)

* Sun Oct 06 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-12
- Add a zero default value to the DISABLETEST and TEST_FAILURES checks
- Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x)

* Fri Oct 04 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-11
- Fix the test for zero failures in the %%check section
- Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x)

* Fri Sep 27 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-10
- Restore a mistakenly removed patch
- Resolves: rhbz#961659 - SQL backend does not reload certificates

* Mon Sep 23 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-9
- Rebuild for the pem module to link with freel from nss-softokn-3.14.3-6.el6
- Related: rhbz#993441 - NSS needs to conform to new FIPS standard. [rhel-6.5.0]
- Related: rhbz#1010224 - NSS 3.15 breaks SSL in OpenLDAP clients

* Thu Sep 19 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-8
- Don't require nss-softokn-fips
- Resolves: rhbz#993441 - NSS needs to conform to new FIPS standard. [rhel-6.5.0]

* Thu Sep 19 2013 Kai Engert <kaie@redhat.com> - 3.15.1-7
- Additional syntax fixes in nss-versus-softoken-test.patch
- Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x)

* Wed Sep 18 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-6
- Fix all.sh test for which application was last build by updating nss-versus-softoken-test.path
- Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x)

* Fri Sep 13 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-5
- Disable the cipher suite already run as part of the nss-softokn build
- Resolves: rhbz#993441 - NSS needs to conform to new FIPS standard. [rhel-6.5.0]

* Fri Sep 13 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-4
- Require nss-softokn-fips
- Resolves: rhbz#993441 - NSS needs to conform to new FIPS standard. [rhel-6.5.0]

* Sat Sep 07 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-3
- Require nspr-4.10.0
- Related: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x)

* Fri Sep 06 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-2
- Fix relative path in %%check section to prevent undetected test failures
- Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x) 

* Fri Sep 06 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-1
- Rebase to NSS_3.15.1_RTM
- Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for FF 24.x) 
- Update patches on account of the shallow tree with the rebase to 3.15.1
- Update the pem module sources  nss-pem-20130405.tar.bz2 with latest patches applied
- Remove patches rendered obsolete by the nss rebase and the updated nss-pem sources
- Enable the iquote.patch to access newly introduced types

* Tue Aug 13 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-37
- Do not hold issuer certificate handles in the crl cache
- Resolves: rhbz#961659 - SQL backend does not reload certificates

* Mon Aug 12 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-36
- Resolves: rhbz#977341 - nss-tools certutil -H does not list all options

* Fri Aug 09 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-35
- Resolves: rhbz#702083 - dont require unique file basenames

* Thu Aug 08 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-34
- Fix race condition in cert code related to smart cards
- Resolves: rhbz#903017 - Firefox hang when CAC/PIV smart card certificates are viewed in the certificate manager

* Thu Jun 13 2013 Kai Engert <kaie@redhat.com> - 3.14.3-33
- Configure libnssckbi.so to use the alternatives system
  in order to prepare for a drop in replacement.
  Please ensure that older packages that don't use the alternatives
  system for libnssckbi.so have a smaller n-v-r.
* Sun May 26 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-5
- Syncup with uptream changes for aes gcm and ecc suiteb
- Enable ecc support for suite b
- Apply several upstream AES GCM fixes
- Use the pristine nss upstream sources with ecc included
- Export NSS_ENABLE_ECC=1 in both the build and the check sections
- Make failed requests for unsupoprted ssl pkcs 11 bypass non fatal
- Resolves: rhbz#882408 - NSS_NO_PKCS11_BYPASS must preserve ABI
- Related:  rhbz#918950  - rebase nss to 3.14.3

* Fri Apr 26 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-4
- Revert to accepting MD5 on digital signatures by default
- Resolves: rhbz#918136 - nss 3.14 - MD5 hash algorithm disabled

* Wed Mar 27 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-3
- Ensure pem uses system freebl as with this update freebl brings in new API's
- Resolves: rhbz#918950 - [RFE][RHEL6] Rebase to nss-3.14.3 to fix the lucky-13 issue

* Tue Mar 26 2013 Elio Maldonado - 3.14.3-2
- Install sechash.h and secmodt.h which are now provided by nss-devel
- Resolves: rhbz#918950 - [RFE][RHEL6] Rebase to nss-3.14.3 to fix the lucky-13 issue
- Remove unsafe -r option from commands that remove headers already shipped by nss-util and nss-softoken

* Sun Mar 24 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-1
- Update to NSS_3.14.3_RTM
- Resolves: rhbz#918950 - [RFE][RHEL6] Rebase to nss-3.14.3 to fix the lucky-13 issue
- Update expired test certificates (fixed in upstream bug 852781)
- Sync up pem module's rsawrapr.c with softoken's upstream changes for nss-3.14.3
- Reactivate the aia tests

* Thu Jan 10 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-12
- Recreate the distrust patch by backporting the upstream one
- Resolves: rhpbz#890914 - Dis-trust TURKTRUST mis-issued *.google.com certificate

* Wed Jan 09 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-11
- Resolves: rhpbz#890914 - Dis-trust TURKTRUST mis-issued *.google.com certificate

* Wed Dec 12 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-10
- Remove a patch that caused a regression
- Resolves: rhbz#883620

* Wed Nov 07 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-9
- Fix locking issue causing curl hangs and authenticate to the correct session
- Resolves: rhbz#872838

* Wed Nov 07 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-8
- PEM peminit returns CKR_CANT_LOCK when needed to inform caller module isn't thread safe
- Resolves: rhbz#555019 - [PEM] invalid writes in multi-threaded libcurl based application

* Thu Nov 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-7
- Add dummy sources file to test for and prevent breaking rhpkg commands
- Enable testing for 'rhpk upload' and 'rhpk new-sources' breakage such as hangs
- Related: rhbz#837089

* Sun Oct 28 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-6
- Update the license to MPLv2.0
- turn off the aia tests
- Resolves: rhbz#837089

* Wed Oct 24 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-5
- Resolves: rhbz#702083 - NSS pem module should not require unique base file names

* Sun Oct 21 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-4
- turn on the aia tests
- update nss-589636.patch to apply to httpdserv

* Fri Oct 12 2012 Kai Engert <kaie@redhat.com> - 3.14.0.0-3
- turn off aia tests for now

* Fri Oct 12 2012 Bob Relyea <rrelyea@redhat.com> - 3.14.0.0-2
- turn off ocsp tests for now

* Thu Oct 11 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.0.0-1
- Rebase to nss-3.14.0.0-1
- Resolves: rhbz#837089
- Update ssl-cbc-random-iv patch for new sources
- Remove patches rendered obsoleted by rebase to 3.14
- Add a patch to enforce no pkcs11 bypass

* Sun Jun 24 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-3
- Resolves: rhbz#830302 - require nspr 4.9.1

* Thu Jun 21 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-2
- Resolves: rhbz#830302 - revert unwanted changes to nss.pc.in

* Wed Jun 20 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-1
- Resolves: rhbz#830302 - Update RHEL 6.x to NSS 3.13.5 and NSPR 4.9.1 for Mozilla 10.0.6

* Mon Jun 04 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-7
- Resolves: rhbz#827351 invalid read and free on invalid cert load failure

* Mon Apr 16 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-6
- Resolves: #rhbz#805232 PEM module may attempt to free uninitialized pointer

* Fri Mar 16 2012 Elio Maldonado Batiz <emaldona@redhat.com> - 3.13.3-5
- Resolves: rhbz#717913 - [PEM] various flaws detected by Coverity
- Require nss-util 3.13.3

* Wed Mar 14 2012 Elio Maldonado Batiz <emaldona@redhat.com> - 3.13.3-4
- Resolves: rhbz#772628 nss_Init leaks memory

* Tue Mar 13 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-3
- Resolves: rhbz#746632 - pem_CreateObject mem leak on non existing file name
- Use completed patch per code review

* Tue Mar 13 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-2
- Resolves: rhbz#746632 - pem_CreateObject mem leak on non existing file name
- Resolves: rhbz#768669 - PEM unregistered callback causes SIGSEGV

* Mon Mar 05 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-1
- Update to 3.13.3
- Resolves: rhbz#798539 - Distrust MITM subCAs issued by TrustWave
- Remove builtins-nssckbi_1_88_rtm.patch which the rebase obsoletes

* Tue Feb 28 2012 Elio Maldonado Batiz <emaldona@redhat.com> - 3.13.1-6
- Resolves: rhbz#746632 - Adjust the patch for new sources

* Tue Feb 28 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-5
- Resolves: rhbz#746632 - pem_CreateObject() leaks memory given a non-existing file name

* Tue Feb 28 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-4
- Resolves: 784674 - Protect NSS_Shutdown from clients that fail to initialize nss

* Mon Feb 20 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-4
- Add two needed patches
- Resolves: rhbz#783315 - Need nss workaround for freebl bug that causes openswan to drop connections
- Resolves: rhbz#747387 - Unable to contact LDAP Server during winsync

* Mon Jan 30 2012 Martin Stransky <stransky@redhat.com> 3.13.1-3
- Rebuild

* Sat Jan 28 2012 Elio Maldonado Batiz <emaldona@redhat.com> - 3.13.1-2
- Resolves: Bug 784490 - CVE-2011-3389
- Activate a patch that was left out in previous build

* Tue Jan 24 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-1
- Resolves: Bug 744070 - Update to 3.13.1
- Resolves: Bug 784674 - nss should protect against being called before nss_Init
- Resolves: Bug 784490 - CVE-2011-3389 HTTPS: block-wise chosen-plaintext attack against SSL/TLS (BEAST)

* Wed Dec 07 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-17
- Resolves: Bug 761086 - Fix nss-735047.patch to not revert the nss-bz689031.patch

* Tue Nov 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-16
- Update builtins certs to those from NSSCKBI_1_88_RTM

* Thu Oct 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-15
- Bug 747387 - Unable to contact LDAP Server during winsync

* Wed Oct 19 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-14
- Add to the spec file the patch for Bug 671266

* Sun Oct 16 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-13
- More coverity related fixes in the pem module

* Sun Oct 16 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-12
- Coverity related fixes

* Tue Sep 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-11
- Add relro support for executables and shared libraries

* Mon Sep 19 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-10
- Add partial RELRO support 

* Fri Sep 02 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-9
- Fix the name of the last patch file

* Fri Sep 02 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-8
- Retagging to pick up two missing commits

* Fri Sep 02 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-7
- Update builtins certs to those from NSSCKBI_1_87_RTM

* Wed Aug 31 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-6
- Update builtins certs to those from NSSCKBI_1_86_RTM

* Tue Aug 30 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-5
- Update builtins certs to those from NSSCKBI_1_85_RTM

* Sun Aug 14 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-4
- Fix CMS to verify signed data when SignerInfo indicates signer by subjectKeyID

* Fri Aug 12 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-3
- Fix pem logging to deal with files originally created by root

* Mon Jul 11 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-2
- Retagging for updated patch missing from previous tag

* Mon Jul 11 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-1
- Update to 3.12.10

* Thu Jun 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-11
- Resolves: rhbz# 703658 - Fix crmf hard-coded maximum size for wrapped private keys

* Thu Jun 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-10
- Resolves: rhbz#688423 - Enable NSS support for pluggable ECC

* Thu Apr 21 2011 Elio Maldonado Batiz <emaldona@redhat.com> - 3.12.9-9
- Add "Conflicts: curl < 7.19.7-26.el6" to fix Bug 694663 

* Thu Apr 07 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-8
- Construct private key nickname based on the full pathname of the pem file

* Wed Apr 06 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-7
- Update expired PayPayEE.cert test certificate
- Conditionalize some database tests on user not being root

* Wed Mar 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-6
- Update to NSS_3.12.9_WITH_CKBI_1_82_RTM

* Tue Mar 01 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-5
- Fix memory leaks caused by SECKEY_ImportDERPublicKey

* Thu Feb 24 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-4
- Short-term fix for ssl test suites hangs on ipv6 type connections

* Thu Feb 17 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-3
- Add requires for pkcs11-devel on nss-softokn-freebl devel
- Run the test suites in check section per packaging guidelines

* Sat Jan 22 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-2
- Prefer user database ca cert trust settings system's ones
- Swap internal key slot on fips mode switches

* Mon Jan 17 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-1
- Update to 3.12.9
- Fix libnsspem to test for and reject directories

* Sat Nov 27 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-2
- Add suppport for pkcs8 formatted keys in the pem module
- Add verify(not md5 size mtime) to configuration files attributes
- Prevent nss-sysinit disabling on package upgrade
- Create pkcs11.txt with correct permissions regardless of current umask
- Add option to setup-nsssysinit.sh to report nss-sysinit status
- Update test certificate which had expired

* Fri Oct 01 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-1
- Update to 3.12.8

* Fri Aug 27 2010 Kai Engert <kengert@redhat.com> - 3.12.7-2
- Increase release version number, no code changes

* Thu Aug 26 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-1
- Update to 3.12.7

* Thu Aug 26 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-6
- Rebuilt

* Thu Aug 26 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-5
- Appying the changes in previous log
- Changing some BuildRequires to >= as well
- Temporarily disabling all tests for faster builds

* Thu Aug 26 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-4
- Change some = to >= in Requires to enable a rebase next

* Mon Jun 07 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-3
- Fix SIGSEGV within CreateObject (#596783)
- Update expired test certificate

* Mon Mar 22 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-2
- Fix nss.pc to not require nss-softokn

* Thu Mar 04 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1.2
- rebuilt using nss-util 3.2.6

* Thu Mar 04 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1.1
- rebuilt using nspr-devel 4.8.4

* Wed Mar 03 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1
- Update to 3.12.6

* Wed Feb 24 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5.99-1
- Update to NSS_3_12_6_RC1
* Mon Jan 25 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-8
- Fix curl related regression and general patch code clean up

* Tue Jan 19 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-7.3
- Resolves: #551784 rebuilt after nss-softokn and nss-util builds
- this will generate the coorect nss.spec

* Sun Jan 17 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-7.2
- rebuilt for RHEL-6 candidate, Resolves: #551784

* Sun Jan 17 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-7.1
- Updated to 3.12.5 from CVS import from Fedora 12
- Moved blank legacy databases to the lookaside cache
- Reenabled the full test suite
- Retagging for a RHEL-6-test-build

* Wed Jan 13 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-7
- Retagged

* Wed Jan 13 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-6
- retagging

* Tue Jan 12 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-2.1
- Fix SIGSEGV on call of NSS_Initialize (#553638)

* Wed Jan 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-2
- bump release number and rebuild

* Wed Jan 06 2010 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.14
- Fix nsssysinit to allow root to modify the nss system database (#547860)

* Wed Jan 06 2010 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.12.1
- Temporarily disabling the ssl tests until Bug 539183 is resolved

* Fri Dec 25 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.11
- Fix an error introduced when adapting the patch for 546211

* Sat Dec 19 2009 Elio maldonado<emaldona@redhat.com> - 3.12.5-1.10
- Remove some left over trace statements from nsssysinit patching

* Thu Dec 17 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.8
- Fix nsssysinit to set the default flags on the crypto module (#545779)
- Fix nsssysinit to enable apps to use the system cert store, patch contributed by David Woodhouse (#546221)
- Fix segmentation fault when listing keys or certs in the database, patch contributed by Kamil Dudka (#540387)
- Sysinit requires coreutils for post install scriplet (#547067)
- Remove redundant header from the pem module

* Wed Dec 09 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-2.1
- Remove unneeded patch

* Fri Dec 04 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.2
- Update to 3.12.5
- CVE-2009-3555 TLS: MITM attacks via session renegotiation

* Mon Oct 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-15
- Require nss-softoken of same arch as nss (#527867)

* Tue Oct 06 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-14
- Fix bug where user was prompted for a password when listing keys on an empty system database (#527048)
- Fix setup-nsssysinit to handle more general flags formats (#527051)

* Sun Sep 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-12
- Fix syntax error in setup-nsssysinit.sh

* Sun Sep 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-11
- Fix sysinit to be under mozilla/security/nss/lib

* Sat Sep 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-10
- Add nss-sysinit activation/deactivation script

* Fri Sep 18 2009 Elio Maldonado<emaldona@redhat.com - 3.12.4-9
- Install blank databases and configuration file for system shared database
- nsssysinit queries system for fips mode before relying on environment variable

* Thu Sep 10 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-8
- Restoring nssutil and -rpath-link to nss-config for now - 522477

* Tue Sep 08 2009 Elio Maldonado<emaldona@redhat.com - 3.12.4-7
- Add the nss-sysinit subpackage

* Tue Sep 08 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-6
- Installing shared libraries to %%{_libdir}

* Mon Sep 07 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-5
- Retagging to pick up new sources

* Mon Sep 07 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-4
- Update pem enabling source tar with latest fixes (509705, 51209)

* Sun Sep 06 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-3
- PEM module implements memory management for internal objects - 509705
- PEM module doesn't crash when processing malformed key files - 512019

* Sat Sep 05 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-2
- Remove symbolic links to shared libraries from devel - 521155
- No rpath-link in nss-softokn-config

* Tue Sep 01 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-1
- Update to 3.12.4

* Mon Aug 31 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-30
- Fix FORTIFY_SOURCE buffer overflows in test suite on ppc and ppc64 - bug 519766
- Fixed requires and buildrequires as per recommendations in spec file review

* Sun Aug 30 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-29
- Restoring patches 2 and 7 as we still compile all sources
- Applying the nss-nolocalsql.patch solves nss-tools sqlite dependency problems

* Sun Aug 30 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-28
- restore require sqlite

* Sat Aug 29 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-27
- Don't require sqlite for nss

* Sat Aug 29 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-26
- Ensure versions in the requires match those used when creating nss.pc

* Fri Aug 28 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-25
- Remove nss-prelink.conf as signed all shared libraries moved to nss-softokn
- Add a temprary hack to nss.pc.in to unblock builds

* Fri Aug 28 2009 Warren Togami <wtogami@redhat.com> - 3.12.3.99.3-24
- caolan's nss.pc patch

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-23
- Bump the release number for a chained build of nss-util, nss-softokn and nss

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-22
- Fix nss-config not to include nssutil
- Add BuildRequires on nss-softokn and nss-util since build also runs the test suite

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-21
- disabling all tests while we investigate a buffer overflow bug

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-20
- disabling some tests while we investigate a buffer overflow bug - 519766

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-19
- remove patches that are now in nss-softokn and
- remove spurious exec-permissions for nss.pc per rpmlint
- single requires line in nss.pc.in

* Wed Aug 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-18
- Fix BuildRequires: nss-softokn-devel release number

* Wed Aug 26 2009 Elio Maldonado<emaldona@redhat.com - 3.12.3.99.3-17
- fix nss.pc.in to have one single requires line

* Tue Aug 25 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-16
- cleanups for softokn

* Tue Aug 25 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-15
- remove the softokn subpackages

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-14
- don install the nss-util pkgconfig bits

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-13
- remove from -devel the 3 headers that ship in nss-util-devel

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-12
- kill off the nss-util nss-util-devel subpackages

* Sun Aug 23 2009 Elio Maldonado+emaldona@redhat.com - 3.12.3.99.3-11
- split off nss-softokn and nss-util as subpackages with their own rpms
- first phase of splitting nss-softokn and nss-util as their own packages

* Thu Aug 20 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-10
- must install libnssutil3.since nss-util is untagged at the moment
- preserve time stamps when installing various files

* Thu Aug 20 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-9
- dont install libnssutil3.so since its now in nss-util

* Thu Aug 06 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-7.1
- Fix spec file problems uncovered by Fedora_12_Mass_Rebuild

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.3.99.3-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Jun 22 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-6
- removed two patch files which are no longer needed and fixed previous change log number
* Mon Jun 22 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-5
- updated pem module incorporates various patches
- fix off-by-one error when computing size to reduce memory leak. (483855)
- fix data type to work on x86_64 systems. (429175)
- fix various memory leaks and free internal objects on module unload. (501080)
- fix to not clone internal objects in collect_objects().  (501118)
- fix to not bypass initialization if module arguments are omitted. (501058)
- fix numerous gcc warnings. (500815)
- fix to support arbitrarily long password while loading a private key. (500180) 
- fix memory leak in make_key and memory leaks and return values in pem_mdSession_Login (501191)
* Mon Jun 08 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-4
- add patch for bug 502133 upstream bug 496997
* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 3.12.3.99.3-3
- rebuild with higher release number for upgrade sanity
* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 3.12.3.99.3-2
- updated to NSS_3_12_4_FIPS1_WITH_CKBI_1_75
* Thu May 07 2009 Kai Engert <kaie@redhat.com> - 3.12.3-7
- re-enable test suite
- add patch for upstream bug 488646 and add newer paypal
  certs in order to make the test suite pass
* Wed May 06 2009 Kai Engert <kaie@redhat.com> - 3.12.3-4
- add conflicts info in order to fix bug 499436
* Tue Apr 14 2009 Kai Engert <kaie@redhat.com> - 3.12.3-3
- ship .chk files instead of running shlibsign at install time
- include .chk file in softokn-freebl subpackage
- add patch for upstream nss bug 488350
* Tue Apr 14 2009 Kai Engert <kaie@redhat.com> - 3.12.3-2
- Update to NSS 3.12.3
* Mon Apr 06 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-7
- temporarily disable the test suite because of bug 494266
* Mon Apr 06 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-6
- fix softokn-freebl dependency for multilib (bug 494122)
* Thu Apr 02 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-5
- introduce separate nss-softokn-freebl package
* Thu Apr 02 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-4
- disable execstack when building freebl
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-3
- add upstream patch to fix bug 483855
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-2
- build nspr-less freebl library
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-1
- Update to NSS_3_12_3_BETA4

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.2.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Oct 22 2008 Kai Engert <kaie@redhat.com> - 3.12.2.0-3
- update to NSS_3_12_2_RC1
- use system zlib
* Tue Sep 30 2008 Dennis Gilmore <dennis@ausil.us> - 3.12.1.1-4
- add sparc64 to the list of 64 bit arches

* Wed Sep 24 2008 Kai Engert <kaie@redhat.com> - 3.12.1.1-3
- bug 456847, move pkgconfig requirement to devel package
* Fri Sep 05 2008 Kai Engert <kengert@redhat.com> - 3.12.1.1-2
- Update to NSS_3_12_1_RC2
* Fri Aug 22 2008 Kai Engert <kaie@redhat.com> - 3.12.1.0-2
- NSS 3.12.1 RC1
* Fri Aug 15 2008 Kai Engert <kaie@redhat.com> - 3.12.0.3-7
- fix bug bug 429175 in libpem module
* Tue Aug 05 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-6
- bug 456847, add Requires: pkgconfig
* Tue Jun 24 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-3
- nss package should own /etc/prelink.conf.d folder, rhbz#452062
- use upstream patch to fix test suite abort
* Mon Jun 02 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-2
- Update to NSS_3_12_RC4
* Mon Apr 14 2008 Kai Engert <kengert@redhat.com> - 3.12.0.1-1
- Update to NSS_3_12_RC2
* Thu Mar 20 2008 Jesse Keating <jkeating@redhat.com> - 3.11.99.5-2
- Zapping old Obsoletes/Provides.  No longer needed, causes multilib headache.
* Mon Mar 17 2008 Kai Engert <kengert@redhat.com> - 3.11.99.5-1
- Update to NSS_3_12_BETA3
* Fri Feb 22 2008 Kai Engert <kengert@redhat.com> - 3.11.99.4-1
- NSS 3.12 Beta 2
- Use /usr/lib{64} as devel libdir, create symbolic links.
* Sat Feb 16 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-6
- Apply upstream patch for bug 417664, enable test suite on pcc.
* Fri Feb 15 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-5
- Support concurrent runs of the test suite on a single build host.
* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-4
- disable test suite on ppc
* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-3
- disable test suite on ppc64

* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-2
- Build against gcc 4.3.0, use workaround for bug 432146
- Run the test suite after the build and abort on failures.

* Thu Jan 24 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-1
* NSS 3.12 Beta 1

* Mon Jan 07 2008 Kai Engert <kengert@redhat.com> - 3.11.99.2b-3
- move .so files to /lib

* Wed Dec 12 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2b-2
- NSS 3.12 alpha 2b

* Mon Dec 03 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2-2
- upstream patches to avoid calling netstat for random data

* Wed Nov 07 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2-1
- NSS 3.12 alpha 2

* Wed Oct 10 2007 Kai Engert <kengert@redhat.com> - 3.11.7-10
- Add /etc/prelink.conf.d/nss-prelink.conf in order to blacklist
  our signed libraries and protect them from modification.

* Thu Sep 06 2007 Rob Crittenden <rcritten@redhat.com> - 3.11.7-9
- Fix off-by-one error in the PEM module

* Thu Sep 06 2007 Kai Engert <kengert@redhat.com> - 3.11.7-8
- fix a C++ mode compilation error

* Wed Sep 05 2007 Bob Relyea <rrelyea@redhat.com> - 3.11.7-7
- Add 3.12 ckfw and libnsspem

* Tue Aug 28 2007 Kai Engert <kengert@redhat.com> - 3.11.7-6
- Updated license tag

* Wed Jul 11 2007 Kai Engert <kengert@redhat.com> - 3.11.7-5
- Ensure the workaround for mozilla bug 51429 really get's built.

* Mon Jun 18 2007 Kai Engert <kengert@redhat.com> - 3.11.7-4
- Better approach to ship freebl/softokn based on 3.11.5
- Remove link time dependency on softokn

* Sun Jun 10 2007 Kai Engert <kengert@redhat.com> - 3.11.7-3
- Fix unowned directories, rhbz#233890

* Fri Jun 01 2007 Kai Engert <kengert@redhat.com> - 3.11.7-2
- Update to 3.11.7, but freebl/softokn remain at 3.11.5.
- Use a workaround to avoid mozilla bug 51429.

* Fri Mar 02 2007 Kai Engert <kengert@redhat.com> - 3.11.5-2
- Fix rhbz#230545, failure to enable FIPS mode
- Fix rhbz#220542, make NSS more tolerant of resets when in the 
  middle of prompting for a user password.

* Sat Feb 24 2007 Kai Engert <kengert@redhat.com> - 3.11.5-1
- Update to 3.11.5
- This update fixes two security vulnerabilities with SSL 2
- Do not use -rpath link option
- Added several unsupported tools to tools package

* Tue Jan  9 2007 Bob Relyea <rrelyea@redhat.com> - 3.11.4-4
- disable ECC, cleanout dead code

* Tue Nov 28 2006 Kai Engert <kengert@redhat.com> - 3.11.4-1
- Update to 3.11.4

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 3.11.3-2
- Revert the attempt to require latest NSPR, as it is not yet available
  in the build infrastructure.

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 3.11.3-1
- Update to 3.11.3

* Thu Aug 03 2006 Kai Engert <kengert@redhat.com> - 3.11.2-2
- Add /etc/pki/nssdb

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 3.11.2-1.1
- rebuild

* Fri Jun 30 2006 Kai Engert <kengert@redhat.com> - 3.11.2-1
- Update to 3.11.2
- Enable executable bit on shared libs, also fixes debug info.

* Wed Jun 14 2006 Kai Engert <kengert@redhat.com> - 3.11.1-2
- Enable Elliptic Curve Cryptography (ECC)

* Fri May 26 2006 Kai Engert <kengert@redhat.com> - 3.11.1-1
- Update to 3.11.1
- Include upstream patch to limit curves

* Wed Feb 15 2006 Kai Engert <kengert@redhat.com> - 3.11-4
- add --noexecstack when compiling assembler on x86_64

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 3.11-3.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 3.11-3.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Jan 19 2006 Ray Strode <rstrode@redhat.com> 3.11-3
- rebuild

* Fri Dec 16 2005 Christopher Aillon <caillon@redhat.com> 3.11-2
- Update file list for the devel packages

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-1
- Update to 3.11

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-0.cvs.2
- Add patch to allow building on ppc*
- Update the pkgconfig file to Require nspr

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-0.cvs
- Initial import into Fedora Core, based on a CVS snapshot of
  the NSS_3_11_RTM tag
- Fix up the pkcs11-devel subpackage to contain the proper headers
- Build with RPM_OPT_FLAGS
- No need to have rpath of /usr/lib in the pc file

* Thu Dec 15 2005 Kai Engert <kengert@redhat.com>
- Adressed review comments by Wan-Teh Chang, Bob Relyea,
  Christopher Aillon.

* Sat Jul 09 2005 Rob Crittenden <rcritten@redhat.com> 3.10-1
- Initial build
