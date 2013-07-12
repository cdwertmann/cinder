#    Copyright 2012 OpenStack LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo.config import cfg

from cinder import exception
from cinder import flags
from cinder.openstack.common import log as logging
from cinder.volume.drivers.san.san import SanISCSIDriver

from random import choice
from time import sleep

LOG = logging.getLogger(__name__)

ds3500_opts = [
               cfg.StrOpt('ds3500_smcli',
                          default='/usr/bin/SMcli',
                          help='The path to the SMcli executable.'),
               cfg.StrOpt('ds3500_iscsi_host',
                          default='',
                          help='The IP address of the iSCSI port.'),
               cfg.StrOpt('ds3500_controller',
                          default='',
                          help='The IP address of the controller.'),
               cfg.StrOpt('ds3500_controller_id',
                          default='a',
                          help='Controller used for new volumes (a or b).'),
               cfg.StrOpt('ds3500_host_group',
                          default='',
                          help='Map volumes to this host group'),
               cfg.StrOpt('ds3500_array',
                          default='',
                          help='Create volumes in this array'),]

FLAGS = flags.FLAGS
FLAGS.register_opts(ds3500_opts)

class DS3500ISCSIDriver(SanISCSIDriver):
    """Executes commands relating to DS3500-hosted ISCSI volumes.
        
        SMcli 192.168.104.20 -n GENI_rack_storage -c 'create logicalDrive array="2" userlabel="test2" capacity=1GB mapping=default;'
        SMcli 192.168.104.20 -n GENI_rack_storage -c 'show logicalDrive ["test2"];'
        
        """
    
    """====================================================================="""
    """ SETUP                                                               """
    """====================================================================="""
        
    def do_setup(self, ctxt):
        """Check that we have all configuration details from the storage."""
        
        LOG.debug(_('enter: do_setup'))
#        self._context = ctxt
#        
#        # Validate that the pool exists
#        ssh_cmd = 'svcinfo lsmdiskgrp -delim ! -nohdr'
#        out, err = self._run_ssh(ssh_cmd)
#        self._assert_ssh_return(len(out.strip()), 'do_setup',
#                                ssh_cmd, out, err)
#        search_text = '!%s!' % self.configuration.storwize_svc_volpool_name
#        if search_text not in out:
#            raise exception.InvalidInput(
#                                         reason=(_('pool %s doesn\'t exist')
#                                                 % self.configuration.storwize_svc_volpool_name))
#        
#        # Check if compression is supported
#        self._compression_enabled = False
#        try:
#            ssh_cmd = 'svcinfo lslicense -delim !'
#            out, err = self._run_ssh(ssh_cmd)
#            license_lines = out.strip().split('\n')
#            for license_line in license_lines:
#                name, foo, value = license_line.partition('!')
#                if name in ('license_compression_enclosures',
#                            'license_compression_capacity') and value != '0':
#                    self._compression_enabled = True
#                    break
#        except exception.ProcessExecutionError:
#            LOG.exception(_('Failed to get license information.'))
#        
#        # Get the iSCSI and FC names of the Storwize/SVC nodes
#        ssh_cmd = 'svcinfo lsnode -delim !'
#        out, err = self._run_ssh(ssh_cmd)
#        self._assert_ssh_return(len(out.strip()), 'do_setup',
#                                ssh_cmd, out, err)
#        
#        nodes = out.strip().split('\n')
#        self._assert_ssh_return(len(nodes),
#                                'do_setup', ssh_cmd, out, err)
#        header = nodes.pop(0)
#        for node_line in nodes:
#            try:
#                node_data = self._get_hdr_dic(header, node_line, '!')
#            except exception.VolumeBackendAPIException:
#                with excutils.save_and_reraise_exception():
#                    self._log_cli_output_error('do_setup',
#                                               ssh_cmd, out, err)
#            node = {}
#            try:
#                node['id'] = node_data['id']
#                node['name'] = node_data['name']
#                node['IO_group'] = node_data['IO_group_id']
#                node['iscsi_name'] = node_data['iscsi_name']
#                node['WWNN'] = node_data['WWNN']
#                node['status'] = node_data['status']
#                node['WWPN'] = []
#                node['ipv4'] = []
#                node['ipv6'] = []
#                node['enabled_protocols'] = []
#                if node['status'] == 'online':
#                    self._storage_nodes[node['id']] = node
#            except KeyError:
#                self._handle_keyerror('lsnode', header)
#        
#        # Get the iSCSI IP addresses and WWPNs of the Storwize/SVC nodes
#        self._get_iscsi_ip_addrs()
#        self._get_fc_wwpns()
#        
#        # For each node, check what connection modes it supports.  Delete any
#        # nodes that do not support any types (may be partially configured).
#        to_delete = []
#        for k, node in self._storage_nodes.iteritems():
#            if ((len(node['ipv4']) or len(node['ipv6']))
#                and len(node['iscsi_name'])):
#                node['enabled_protocols'].append('iSCSI')
#                self._enabled_protocols.add('iSCSI')
#            if len(node['WWPN']):
#                node['enabled_protocols'].append('FC')
#                self._enabled_protocols.add('FC')
#            if not len(node['enabled_protocols']):
#                to_delete.append(k)
#        
#        for delkey in to_delete:
#            del self._storage_nodes[delkey]
#        
#        # Make sure we have at least one node configured
#        self._driver_assert(len(self._storage_nodes),
#                            _('do_setup: No configured nodes'))
#        
#        LOG.debug(_('leave: do_setup'))
    
    
    def check_for_setup_error(self):
        """Ensure that the flags are set properly."""
        LOG.debug(_('enter: check_for_setup_error'))
#        
#        required_flags = ['san_ip', 'san_ssh_port', 'san_login',
#                          'storwize_svc_volpool_name']
#        for flag in required_flags:
#            if not self.configuration.safe_get(flag):
#                raise exception.InvalidInput(reason=_('%s is not set') % flag)
#        
#        # Ensure that either password or keyfile were set
#        if not (self.configuration.san_password or
#                self.configuration.san_private_key):
#            raise exception.InvalidInput(
#                                         reason=_('Password or SSH private key is required for '
#                                                  'authentication: set either san_password or '
#                                                  'san_private_key option'))
#        
#        # Check that flashcopy_timeout is not more than 10 minutes
#        flashcopy_timeout = self.configuration.storwize_svc_flashcopy_timeout
#        if not (flashcopy_timeout > 0 and flashcopy_timeout <= 600):
#            raise exception.InvalidInput(
#                                         reason=_('Illegal value %d specified for '
#                                                  'storwize_svc_flashcopy_timeout: '
#                                                  'valid values are between 0 and 600')
#                                         % flashcopy_timeout)
#        
#        opts = self._build_default_opts()
#        self._check_vdisk_opts(opts)
#        
#        LOG.debug(_('leave: check_for_setup_error'))
    
    def __init__(self, *cmd, **kwargs):
        LOG.debug(_('enter: __init__'))        
        super(DS3500ISCSIDriver, self).__init__(*cmd,
                                                 execute=self._execute,
                                                 **kwargs)
        self.configuration.append_config_values(ds3500_opts)
        self.configuration.ds3500_controller_id=self.configuration.ds3500_controller_id.lower()
        if self.configuration.ds3500_controller_id == "a":
            self.numeric_controller_id=1
        elif self.configuration.ds3500_controller_id == "b":
            self.numeric_controller_id=2
        else:
            msg = _('Invalid controller ID: "%s". '
                    'Must be a or b.') % self.configuration.ds3500_controller_id
            raise exception.VolumeBackendAPIException(data=msg)
        
        self.iscsi_host_pool=self.configuration.ds3500_iscsi_host.split(',')
        self.iscsi_target = None
        self.free_luns=[]
        #self.iscsi_target=self._get_iscsi_target()
    


    """====================================================================="""
    """ INITIALIZE/TERMINATE CONNECTIONS                                    """
    """====================================================================="""
    
    
    def initialize_connection(self, volume, connector):
        """Perform the necessary work so that an iSCSI/FC connection can
            be made.
            
            To be able to create an iSCSI/FC connection from a given host to a
            volume, we must:
            1. Translate the given iSCSI name or WWNN to a host name
            2. Create new host on the storage system if it does not yet exist
            3. Map the volume to the host if it is not already done
            4. Return the connection information for relevant nodes (in the
            proper I/O group)
            
            """
        
#        LOG.debug(_('enter: initialize_connection: volume %(vol)s with '
#                    'connector %(conn)s') % {'vol': str(volume),
#                  'conn': str(connector)})
#        
#        vol_opts = self._get_vdisk_params(volume['volume_type_id'])
#        host_name = connector['host']
#        volume_name = volume['name']
#        
#        # Check if a host object is defined for this host name
#        host_name = self._get_host_from_connector(connector)
#        if host_name is None:
#            # Host does not exist - add a new host to Storwize/SVC
#            host_name = self._create_host(connector)
#            # Verify that create_new_host succeeded
#            self._driver_assert(
#                                host_name is not None,
#                                _('_create_host failed to return the host name.'))
#        
#        if vol_opts['protocol'] == 'iSCSI':
#            chap_secret = self._get_chap_secret_for_host(host_name)
#            if chap_secret is None:
#                chap_secret = self._add_chapsecret_to_host(host_name)
#        
#        volume_attributes = self._get_vdisk_attributes(volume_name)
#        lun_id = self._map_vol_to_host(volume_name, host_name)
#        
#        self._driver_assert(volume_attributes is not None,
#                            _('initialize_connection: Failed to get attributes'
#                              ' for volume %s') % volume_name)
#        
#        try:
#            preferred_node = volume_attributes['preferred_node_id']
#            IO_group = volume_attributes['IO_group_id']
#        except KeyError as e:
#            LOG.error(_('Did not find expected column name in '
#                        'lsvdisk: %s') % str(e))
#            exception_msg = (_('initialize_connection: Missing volume '
#                               'attribute for volume %s') % volume_name)
#            raise exception.VolumeBackendAPIException(data=exception_msg)
#        
#        try:
#            # Get preferred node and other nodes in I/O group
#            preferred_node_entry = None
#            io_group_nodes = []
#            for k, node in self._storage_nodes.iteritems():
#                if vol_opts['protocol'] not in node['enabled_protocols']:
#                    continue
#                if node['id'] == preferred_node:
#                    preferred_node_entry = node
#                if node['IO_group'] == IO_group:
#                    io_group_nodes.append(node)
#            
#            if not len(io_group_nodes):
#                exception_msg = (_('initialize_connection: No node found in '
#                                   'I/O group %(gid)s for volume %(vol)s') %
#                                 {'gid': IO_group, 'vol': volume_name})
#                raise exception.VolumeBackendAPIException(data=exception_msg)
#            
#            if not preferred_node_entry and not vol_opts['multipath']:
#                # Get 1st node in I/O group
#                preferred_node_entry = io_group_nodes[0]
#                LOG.warn(_('initialize_connection: Did not find a preferred '
#                           'node for volume %s') % volume_name)
#            
#            properties = {}
#            properties['target_discovered'] = False
#            properties['target_lun'] = lun_id
#            properties['volume_id'] = volume['id']
#            if vol_opts['protocol'] == 'iSCSI':
#                type_str = 'iscsi'
#                # We take the first IP address for now. Ideally, OpenStack will
#                # support iSCSI multipath for improved performance.
#                if len(preferred_node_entry['ipv4']):
#                    ipaddr = preferred_node_entry['ipv4'][0]
#                else:
#                    ipaddr = preferred_node_entry['ipv6'][0]
#                properties['target_portal'] = '%s:%s' % (ipaddr, '3260')
#                properties['target_iqn'] = preferred_node_entry['iscsi_name']
#                properties['auth_method'] = 'CHAP'
#                properties['auth_username'] = connector['initiator']
#                properties['auth_password'] = chap_secret
#            else:
#                type_str = 'fibre_channel'
#                conn_wwpns = self._get_conn_fc_wwpns(host_name)
#                if not vol_opts['multipath']:
#                    if preferred_node_entry['WWPN'] in conn_wwpns:
#                        properties['target_wwn'] = preferred_node_entry['WWPN']
#                    else:
#                        properties['target_wwn'] = conn_wwpns[0]
#                else:
#                    properties['target_wwn'] = conn_wwpns
#        except Exception:
#            with excutils.save_and_reraise_exception():
#                self.terminate_connection(volume, connector)
#                LOG.error(_('initialize_connection: Failed to collect return '
#                            'properties for volume %(vol)s and connector '
#                            '%(conn)s.\n') % {'vol': str(volume),
#                          'conn': str(connector)})
#        
#        LOG.debug(_('leave: initialize_connection:\n volume: %(vol)s\n '
#                    'connector %(conn)s\n properties: %(prop)s')
#                  % {'vol': str(volume),
#                  'conn': str(connector),
#                  'prop': str(properties)})
#        
#        return {'driver_volume_type': type_str, 'data': properties, }
    
    def terminate_connection(self, volume, connector, **kwargs):
        """Cleanup after an iSCSI connection has been terminated.
            
            When we clean up a terminated connection between a given connector
            and volume, we:
            1. Translate the given connector to a host name
            2. Remove the volume-to-host mapping if it exists
            3. Delete the host if it has no more mappings (hosts are created
            automatically by this driver when mappings are created)
            """
#        LOG.debug(_('enter: terminate_connection: volume %(vol)s with '
#                    'connector %(conn)s') % {'vol': str(volume),
#                  'conn': str(connector)})
#        
#        vol_name = volume['name']
#        host_name = self._get_host_from_connector(connector)
#        # Verify that _get_host_from_connector returned the host.
#        # This should always succeed as we terminate an existing connection.
#        self._driver_assert(
#                            host_name is not None,
#                            _('_get_host_from_connector failed to return the host name '
#                              'for connector'))
#        
#        # Check if vdisk-host mapping exists, remove if it does
#        mapping_data = self._get_hostvdisk_mappings(host_name)
#        if vol_name in mapping_data:
#            ssh_cmd = 'svctask rmvdiskhostmap -host %s %s' % \
#                (host_name, vol_name)
#            out, err = self._run_ssh(ssh_cmd)
#            # Verify CLI behaviour - no output is returned from
#            # rmvdiskhostmap
#            self._assert_ssh_return(len(out.strip()) == 0,
#                                    'terminate_connection', ssh_cmd, out, err)
#            del mapping_data[vol_name]
#        else:
#            LOG.error(_('terminate_connection: No mapping of volume '
#                        '%(vol_name)s to host %(host_name)s found') %
#                      {'vol_name': vol_name, 'host_name': host_name})
#        
#        # If this host has no more mappings, delete it
#        if not mapping_data:
#            self._delete_host(host_name)
#        
#        LOG.debug(_('leave: terminate_connection: volume %(vol)s with '
#                    'connector %(conn)s') % {'vol': str(volume),
#                  'conn': str(connector)})
    
    def ensure_export(self, context, volume):
        """Synchronously recreates an export for a logical volume."""
        return self._do_export(volume, False)

    def create_export(self, context, volume):
        return self._do_export(volume, True)

    def _do_export(self, volume, create_flag):
        LOG.debug("do export %s" % volume['id'])
        if not self.iscsi_target:
            self.iscsi_target=self._get_iscsi_target()
        lun=-1
        if not create_flag:
            lun=self._get_lun(volume)
        if lun==-1:
            vol = self._build_vol_name(volume)
            for a in xrange(5):
                free_lun=self._get_free_lun()
                cmd = 'set logicalDrive ["%s"] logicalUnitNumber=%s hostGroup="%s";' % (vol,free_lun,self.configuration.ds3500_host_group)
                LOG.debug("Trying to assign LUN %s to drive %s" % (free_lun, volume['id']))
                if self._execute_with_retry(cmd,1):
                    lun=free_lun
                    if lun in self.free_luns:
                        self.free_luns.remove(lun)
                    break
                self._sync_free_luns
        
        if lun==-1:
            msg = 'Unable to assign LUN to volume: "%s". Try again later.' % volume['id']
            raise exception.VolumeBackendAPIException(data=msg)
        
        model_update = {}
        model_update['provider_location'] = "%s:%s,%s %s %s" % (choice(self.iscsi_host_pool), self.configuration.iscsi_port, self.numeric_controller_id, self.iscsi_target, lun)
        return model_update

    def remove_export(self, context, volume):
        """Removes an export for a logical volume."""
        
        vol = self._build_vol_name(volume)
        cmd = 'remove logicalDrive ["%s"] lunMapping hostGroup="%s";' % (vol,self.configuration.ds3500_host_group)
        self._execute(cmd)
        self._sync_free_luns


    """====================================================================="""
    """ VOLUMES/SNAPSHOTS                                                   """
    """====================================================================="""

    def create_volume(self, volume):
        """Creates a volume."""
        vol = self._build_vol_name(volume)
        if int(volume['size']) == 0:
            volume['size']=1
        cmd = 'create logicalDrive array="%s" userlabel="%s" capacity=%sGB owner=%s;' % (self.configuration.ds3500_array, vol, volume['size'], self.configuration.ds3500_controller_id)
        
        if not self._execute_with_retry(cmd):
            msg = 'Unable to create volume: "%s".' % volume['id']
            raise exception.VolumeBackendAPIException(data=msg)


    def delete_volume(self, volume):
        """Deletes a volume."""
        vol = self._build_vol_name(volume)
        # initialize doesn't work with snapshots
        #cmd = 'start logicalDrive ["%s"] initialize; delete logicalDrive ["%s"];' % (vol,vol)
        cmd = 'delete logicalDrive ["%s"];' % (vol)
        if not self._execute_with_retry(cmd):
            msg = 'Unable to delete volume: "%s".' % volume['id']
            raise exception.VolumeBackendAPIException(data=msg)

    def create_snapshot(self, snapshot):
        LOG.debug(vars(snapshot))
        #source_vol = self.db.volume_get(self._context, snapshot['volume_id'])
        #opts = self._get_vdisk_params(source_vol['volume_type_id'])
        opts = None
        self._create_copy(src_vdisk=snapshot['volume_id'],
                          tgt_vdisk=snapshot['id'],
                          full_copy=False,
                          opts=opts,
                          src_id=snapshot['volume_id'],
                          from_vol=True)

    def delete_snapshot(self, snapshot):
        self.delete_volume(snapshot)

    def create_volume_from_snapshot(self, volume, snapshot):
        if volume['size'] != snapshot['volume_size']:
            exception_message = (_('create_volume_from_snapshot: '
                                   'Source and destination size differ.'))
            raise exception.VolumeBackendAPIException(data=exception_message)
        
        opts = None
        self._create_copy(src_vdisk=snapshot['id'],
                          tgt_vdisk=volume['id'],
                          full_copy=True,
                          opts=opts,
                          src_id=snapshot['id'],
                          from_vol=False)

    def create_cloned_volume(self, tgt_volume, src_volume):
        if src_volume['size'] != tgt_volume['size']:
            exception_message = (_('create_cloned_volume: '
                                   'Source and destination size differ.'))
            raise exception.VolumeBackendAPIException(data=exception_message)
        
        opts = None
        self._create_copy(src_vdisk=src_volume['id'],
                          tgt_vdisk=tgt_volume['id'],
                          full_copy=True,
                          opts=opts,
                          src_id=src_volume['id'],
                          from_vol=True)

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        opts = self._get_vdisk_params(volume['volume_type_id'])
        if opts['protocol'] == 'iSCSI':
            # Implemented in base iSCSI class
            return super(DS3500ISCSIDriver, self).copy_image_to_volume(
                                                                       context, volume, image_service, image_id)
        else:
            raise NotImplementedError()

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        opts = self._get_vdisk_params(volume['volume_type_id'])
        if opts['protocol'] == 'iSCSI':
            # Implemented in base iSCSI class
            return super(DS3500ISCSIDriver, self).copy_volume_to_image(
                                                                       context, volume, image_service, image_meta)
        else:
            raise NotImplementedError()


    """====================================================================="""
    """ MISC/HELPERS                                                        """
    """====================================================================="""
    
    def get_volume_stats(self, refresh=False):
        """Get volume status.
            If 'refresh' is True, run update the stats first."""
        if refresh:
            self._update_volume_status()
        
        return self._stats

    def _update_volume_status(self):
        """Retrieve status info from volume group."""

        LOG.debug(_("Updating volume status"))
        data = {}
        backend_name = self.configuration.safe_get('volume_backend_name')
        data["volume_backend_name"] = backend_name or 'Generic_iSCSI'
        data["vendor_name"] = 'IBM'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = 'iSCSI'

        data['total_capacity_gb'] = 'infinite' # to be overwritten
        data['free_capacity_gb'] = 'infinite' # to be overwritten
        data['reserved_percentage'] = 0
        data['QoS_support'] = False

        cmd = 'show array ["%s"];' % self.configuration.ds3500_array
        (out, _err) = self._execute(cmd)
        lines = self._collect_lines(out)
        for line in lines:
            items = line.split()
            if len(items) > 2:
                if items[0] == "Capacity:":
                    data['total_capacity_gb'] = float(items[1].strip().replace(',',''))
                elif items[0] == "Free" and items[1] == "Capacity:":
                    data['free_capacity_gb'] = float(items[2].strip().replace(',',''))

        self._stats = data

    def _create_copy(self, src_vdisk, tgt_vdisk, full_copy, opts, src_id,
                     from_vol):
        """Create a new snapshot using FlashCopy."""
        
        LOG.debug(_('enter: _create_copy: snapshot %(tgt_vdisk)s from '
                    'vdisk %(src_vdisk)s') %
                  {'tgt_vdisk': tgt_vdisk, 'src_vdisk': src_vdisk})
        
#        src_vdisk_attributes = self._get_vdisk_attributes(src_vdisk)
#        if src_vdisk_attributes is None:
#            exception_msg = (
#                             _('_create_copy: Source vdisk %s does not exist')
#                             % src_vdisk)
#            LOG.error(exception_msg)
#            if from_vol:
#                raise exception.VolumeNotFound(exception_msg,
#                                               volume_id=src_id)
#            else:
#                raise exception.SnapshotNotFound(exception_msg,
#                                                 snapshot_id=src_id)
        
#        self._driver_assert(
#                            'capacity' in src_vdisk_attributes,
#                            _('_create_copy: cannot get source vdisk '
#                              '%(src)s capacity from vdisk attributes '
#                              '%(attr)s')
#                            % {'src': src_vdisk,
#                            'attr': src_vdisk_attributes})
        
        vol={}
        vol['size']=1
        vol['id']=tgt_vdisk
        self.create_volume(vol)

        cmd = 'create VolumeCopy source="%s" target="%s";' % (src_vdisk[:30], tgt_vdisk[:30])
        if not self._execute_with_retry(cmd):
            msg = 'Unable to copy volume "%s" to "%s".' % (src_vdisk[:30], tgt_vdisk[:30])
            raise exception.VolumeBackendAPIException(data=msg)

        # Check every 10s whether copy has completed
        while True:
            sleep(10)
            cmd = 'show volumeCopy target ["%s"];' % tgt_vdisk[:30]
            (out, _err) = self._execute(cmd)
            if "Copy status: In progress" not in out: break
        
        LOG.debug(_('leave: _create_copy: snapshot %(tgt_vdisk)s from '
                    'vdisk %(src_vdisk)s') %
                  {'tgt_vdisk': tgt_vdisk, 'src_vdisk': src_vdisk})
    
    def _get_lun(self, volume):
        vol = self._build_vol_name(volume)
        cmd = 'show logicalDrive ["%s"];' % vol
        (out, _err) = self._execute(cmd)
        lines = self._collect_lines(out)
        for line in lines:
            items = line.split()
            if len(items) == 2:
                if items[0] == "LUN:":
                    lun = int(items[1].strip())
                    return lun
    
        return -1

    def _get_free_lun(self):
        self.free_luns.sort()
        #LOG.debug(self.free_luns)
        if len(self.free_luns)>0:
            return self.free_luns.pop(0)
        else:
            self._sync_free_luns()
            return self.free_luns.pop(0)

        msg = _('No free LUN available in host group %s. '
                'Output=%s') % (self.configuration.ds3500_host_group, out)
        raise exception.VolumeBackendAPIException(data=msg)

    def _sync_free_luns(self):
        cmd = 'show storageSubsystem lunMappings hostGroup ["%s"];' % self.configuration.ds3500_host_group
        (out, _err) = self._execute(cmd)
        lines = self._collect_lines(out)
        used_luns=[]
        all_luns=[]
        for line in lines:
            items=line.split()
            if len(items) > 8 and items[1].isdigit() and int(items[1])<256:
                used_luns.append(int(items[1]))

        used_luns.sort()
        LOG.debug("used lun list" % used_luns)
        for l in range(0, 255):
            all_luns.append(l)
        
        self.free_luns = list(set(all_luns) - set(used_luns))

    def _get_iscsi_target(self):
        (out, _err) = self._execute('show storageSubsystem summary;')
        lines = self._collect_lines(out)
        for line in lines:
            items = line.split()
            if len(items) == 3 and items[0] == "Target" and items[1] == "name:":
                return items[2].strip()

        msg = _(' Could not retrieve iSCSI target name '
                'Output=%(out)s') % locals()
        raise exception.VolumeBackendAPIException(data=msg)
    
    def _collect_lines(self, data):
        """Split lines from data into an array, trimming them """
        matches = []
        for line in data.splitlines():
            match = line.strip()
            matches.append(match)
        return matches
    
    def _get_prefixed_values(self, data, prefix):
        """Collect lines which start with prefix; with trimming"""
        matches = []
        for line in data.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                match = line[len(prefix):]
                match = match.strip()
                matches.append(match)
        return matches

    def _execute(self, cmd, **kwargs):
        new_cmd = ['/usr/bin/sudo', self.configuration.ds3500_smcli, self.configuration.ds3500_controller, '-quick', '-n', self.configuration.san_clustername,'-c', '\''+cmd+'\'']
        return super(DS3500ISCSIDriver, self)._execute(*new_cmd,
                                                       **kwargs)
    
    def _execute_with_retry(self, cmd, attempts=5):
        for a in xrange(attempts):
            (out, _err) = self._execute(cmd)
            if "Script execution complete." in out:
                return True
            else:
                LOG.debug(out)
        
        return False
    
    def _build_vol_name(self, volume):
        # Volume names are limited to 30 characters :(
        return volume['id'][:30]
