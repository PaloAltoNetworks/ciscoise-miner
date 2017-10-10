Cisco ISE pxGrid Session Miner
==============================

Overview
--------

The ``miner.PxgridRestSession()`` class implements an
**EXPERIMENTAL**
`MineMeld <https://live.paloaltonetworks.com/t5/MineMeld/ct-p/MineMeld>`_
miner to
poll for sessions from ISE using the pxGrid REST API request used in
the pxGrid SDK for bulk session download.

It polls for all ISE sessions at a configurable time interval (default
5 minutes).  IPv4 or IPv6 indicators are published with **SGT**
(Security Group Tag) and/or **user** attributes.  Indicators with SGT
can be pushed to PAN-OS as ``registered-ip`` objects for use in
Dynamic Address Groups (DAGs) using the
``minemeld.ft.dag.DagPusher()`` class.

There is currently not a MineMeld output node to push ip-user mappings
to PAN-OS.

ISE pxGrid Configuration
------------------------

ISE must be configured for pxGrid.  The pxGrid client must use
either SSL client certificate authentication or username and
password authentication.  Configuration guides for these methods
include:

- Configure and Test Integration with Cisco pxGrid using ISE 2.0

  https://communities.cisco.com/docs/DOC-68291

- Using Username and Password for pxGrid Client

  https://developer.cisco.com/fileMedia/download/5d7f78b8-c5ec-4b1d-a3f0-3629b4c83807

.. note::
   Username and password authentication is not currently
   handled seamlessly.  The password provided by ISE when you create
   an account with the username/password auth method is not the
   password that must be base64 encoded in the HTTP Authorization
   header for the request; it appears it is encoded in some way.  This
   can be made to work if you sniff the encoded password in the SSL
   session HTTP Authorization header using something like Wireshark,
   however the details of this are not provided.

After you have configured pxGrid with self-signed certificates
as described in
`DOC-68291
<https://communities.cisco.com/docs/DOC-68291>`_
above, registered the pxGrid client to the ISE
pxGrid node, and verified the configuration using one of the
sample scripts from the SDK (e.g., ``session_download.sh``),
you can perform the following steps to:

- Convert the PKCS12 client key pair to PEM with no passphrase
- Export the ISE pxGrid SSL server certificate

.. note::
   The `Python requests module
   <http://docs.python-requests.org/en/master/user/advanced/>`_ used
   for HTTPS connections to pxGrid does not currently support
   encrypted key files.

Convert the PKCS12 key pair to PEM with no passphrase
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In step 4 of `DOC-68291
<https://communities.cisco.com/docs/DOC-68291>`_ ``alpha.p12`` was
created containing the client public key certificate and private key.  The
PKCS12 key pair is converted to PEM with no passphrase using the OpenSSL
command line tool:
::

 $ openssl pkcs12 -in alpha.p12 -out alpha-nopw.pem -nodes
 Enter Import Password:
 MAC verified OK

.. note::
   The openssl ``-nodes`` argument means *no DES*.

This file will be used for the ``cert`` argument below.

Export the ISE pxGrid SSL server certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In step 6 of `DOC-68291
<https://communities.cisco.com/docs/DOC-68291>`_
the ISE public key certificate was exported and
renamed to ``isemnt.pem``.

This file will be used for the ``verify`` argument below.

MineMeld Node Configuration
---------------------------

The most common configuration will be a ``pxgrid_rest_session``
miner node and a ``sgt_dag`` output node as follows:
::

 nodes:
   pxgrid_rest_session-1506445499389:
     inputs: []
     output: true
     prototype: ciscoise.pxgrid_rest_session
   sgt_dag-1507045805691:
     inputs:
     - pxgrid_rest_session-1506445499389
     output: false
     prototype: ciscoise.sgt_dag

``pxgrid_rest_session`` Prototype Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pxgrid_rest_session``  is configured in the prototype
``config`` dictionary, and using a side config file containing
YAML.  The side config resides in the ``/opt/minemeld/local/config``
directory and is named *node*\ ``_side_config.yml``, where *node* is
the name of the miner node.

.. note::
   Non-null variables in the side config will override variables set
   in the prototype config.

The following configuration variables are available:

=========================  ========    ==============================     ==========
Variable Name              Type        Description                        Default
=========================  ========    ==============================     ==========
attribute_prefix           string      prefix for sgt/user attributes     ise\_
hostname                   string      ISE hostname                       null
username                   string      pxGrid client name/username        null
password                   string      pxGrid password                    null
cert                       string      pxGrid client key/certificate      null
verify                     string      pxGrid server certificate          null
                           boolean
timeout                    float       HTTPS connection timeout           no timeout
=========================  ========    ==============================     ==========

.. note::
   If the *subjectAltName* or *commonName* in the certificate
   does not match the hostname used, you can set up a hostname in DNS
   or a local host file, or disable server certificate verification
   with ``verify: false``.

Sample side config:
::

 $ pwd
 /opt/minemeld/local/config

 $ cat pxgrid_rest_session-1506445499389_side_config.yml 
 hostname: ise.paloaltonetworks.local
 username: sim01
 cert: /opt/minemeld/local/certs/miners/alpha2-nopw.pem
 verify: /opt/minemeld/local/certs/miners/isemnt.pem

Install Client and Server Key Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is suggested to install the client and server key files
in the ``/opt/minemeld/local/certs/miners/`` directory and
ensure its permissions are 750 minemeld:minemeld:
::

 $ ls -ld /opt/minemeld/local/certs/miners
 drwxr-x--- 2 minemeld minemeld 4096 Oct  4 20:05 /opt/minemeld/local/certs/miners
 $ ls -l /opt/minemeld/local/certs/miners/*.pem
 -rw-r--r-- 1 minemeld minemeld 5516 Oct  4 20:04 /opt/minemeld/local/certs/miners/alpha-nopw.pem
 -rw-r--r-- 1 minemeld minemeld 1192 Oct  4 20:04 /opt/minemeld/local/certs/miners/isemnt.pem

``sgt_dag`` Prototype Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``sgt_dag`` is configured in the prototype ``config``
dictionary, and PAN-OS API arguments are configured in a device list
file containing YAML.  The device list resides in the
``/opt/minemeld/local/config`` directory and is named *node*\
``_device_list.yml``, where *node* is the name of the output node.

``sgt_dag`` prototype configuration variables:

=========================  ========    ==============================     ==========
Variable Name              Type        Description                        Default
=========================  ========    ==============================     ==========
persistent_registered_ips  boolean     registered-ip persistent flag      false
tag_attributes             list        attribute names to register        ise_sgt
=========================  ========    ==============================     ==========

.. note::
   The persistent flag is discussed at:
   http://api-lab.paloaltonetworks.com/registered-ip.html#persistent-attribute

device config configuration variables:

=========================  ========    ==============================     ==========
Variable Name              Type        Description                        Default
=========================  ========    ==============================     ==========
hostname                   string      PAN-OS hostname                    null
api_username               string      user for type=keygen               null
api_password               string      password for type=keygen           null
api_key                    string      key for API requests               null
=========================  ========    ==============================     ==========

.. note::
   device config is a list of dictionaries.

   You must specify either ``api_key`` or ``api_username`` and ``api_password``.

Sample device config:
::

 $ cat sgt_dag-1507045805691_device_list.yml
 - hostname: 192.168.1.101
   api_username: admin
   api_password: admin

 - hostname: 192.168.1.102
   api_key: LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09

ciscoise-miner Installation
---------------------------

The ciscoise-miner is available as a MineMeld extension.  In the WebUI
under SYSTEM->EXTENSIONS you upload the extension from a wheel package
or from git (https://github.com/PaloAltoNetworks/ciscoise-miner.git),
then activate the extension.  The ``pxgrid_rest_session`` and
``sgt_dag`` prototypes are then available to configure nodes.
