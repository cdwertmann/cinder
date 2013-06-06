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
        
        Basic setup for a DS3500 iSCSI server:
        
        pkg install storage-server SUNWiscsit
        
        svcadm enable stmf
        
        svcadm enable -r svc:/network/iscsi/target:default
        
        pfexec itadm create-tpg e1000g0 ${MYIP}
        
        pfexec itadm create-target -t e1000g0
        
        
        Then grant the user that will be logging on lots of permissions.
        I'm not sure exactly which though:
        
        zfs allow justinsb create,mount,destroy rpool
        
        usermod -P'File System Management' justinsb
        
        usermod -P'Primary Administrator' justinsb
        
        Also make sure you can login using san_login & san_password/san_private_key
        
        SMcli 192.168.104.20 -n GENI_rack_storage -c 'create logicalDrive array="2" userlabel="test2" capacity=1GB mapping=default;'
        SMcli 192.168.104.20 -n GENI_rack_storage -c 'show logicalDrive ["test2"];'
        
        """
    def __init__(self, *cmd, **kwargs):
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
    

#    def _view_exists(self, luid):
#        (out, _err) = self._execute('/usr/sbin/stmfadm',
#                                    'list-view', '-l', luid,
#                                    check_exit_code=False)
#        if "no views found" in out:
#            return False
#        
#        if "View Entry:" in out:
#            return True
#        msg = _("Cannot parse list-view output: %s") % out
#        raise exception.VolumeBackendAPIException(data=msg)
    
#    def _get_target_groups(self):
#        """Gets list of target groups from host."""
#        (out, _err) = self._execute('/usr/sbin/stmfadm', 'list-tg')
#        matches = self._get_prefixed_values(out, 'Target group: ')
#        LOG.debug("target_groups=%s" % matches)
#        return matches
#    
#    def _target_group_exists(self, target_group_name):
#        return target_group_name not in self._get_target_groups()
#    
#    def _get_target_group_members(self, target_group_name):
#        (out, _err) = self._execute('/usr/sbin/stmfadm',
#                                    'list-tg', '-v', target_group_name)
#        matches = self._get_prefixed_values(out, 'Member: ')
#        LOG.debug("members of %s=%s" % (target_group_name, matches))
#        return matches
#    
#    def _is_target_group_member(self, target_group_name, iscsi_target_name):
#        return iscsi_target_name in (
#                                     self._get_target_group_members(target_group_name))
#    
#    def _get_iscsi_targets(self):
#        (out, _err) = self._execute('/usr/sbin/itadm', 'list-target')
#        matches = self._collect_lines(out)
#        
#        # Skip header
#        if len(matches) != 0:
#            assert 'TARGET NAME' in matches[0]
#            matches = matches[1:]
#        
#        targets = []
#        for line in matches:
#            items = line.split()
#            assert len(items) == 3
#            targets.append(items[0])
#        
#        LOG.debug("_get_iscsi_targets=%s" % (targets))
#        return targets
#    
#    def _iscsi_target_exists(self, iscsi_target_name):
#        return iscsi_target_name in self._get_iscsi_targets()
#    
#    def _build_zfs_poolname(self, volume):
#        zfs_poolname = '%s%s' % (self.configuration.san_zfs_volume_base, volume['name'])
#        return zfs_poolname
    
    def _build_vol_name(self, volume):
        # Volume names are limited to 30 characters :(
        return volume['id'][:30]
    
    def create_volume(self, volume):
        """Creates a volume."""
        vol = self._build_vol_name(volume)
        if int(volume['size']) == 0:
            volume['size']=1
        cmd = 'create logicalDrive array="%s" userlabel="%s" capacity=%sGB owner=%s;' % (self.configuration.ds3500_array, vol, volume['size'], self.configuration.ds3500_controller_id)

        if not self._execute_with_retry(cmd):
            msg = 'Unable to create volume: "%s".' % volume['id']
            raise exception.VolumeBackendAPIException(data=msg)

#        if int(volume['size']) == 0:
#            sizestr = '100M'
#        else:
#            sizestr = '%sG' % volume['size']
#        
#        zfs_poolname = self._build_zfs_poolname(volume)
#        
#        # Create a zfs volume
#        cmd = ['/usr/sbin/zfs', 'create']
#        if self.configuration.san_thin_provision:
#            cmd.append('-s')
#        cmd.extend(['-V', sizestr])
#        cmd.append(zfs_poolname)
#        cmd = ['/bin/echo', 'create', '>/tmp/cinder']
#        self._execute(*cmd)

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
        LOG.debug(self.free_luns)
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
    
    def delete_volume(self, volume):
        """Deletes a volume."""
        vol = self._build_vol_name(volume)
        cmd = 'start logicalDrive ["%s"] initialize; delete logicalDrive ["%s"];' % (vol,vol)
        self._execute(cmd)
    
    def local_path(self, volume):
        # TODO(justinsb): Is this needed here?
        escaped_group = self.configuration.volume_group.replace('-', '--')
        escaped_name = volume['name'].replace('-', '--')
        return "/dev/mapper/%s-%s" % (escaped_group, escaped_name)
    
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

    def get_volume_stats(self, refresh=False):
        if refresh or not self._stats:
            self._stats = dict(
                volume_backend_name=self.configuration.volume_backend_name or 'DS3500',
                vendor_name='Open Source',
                driver_version='1.0',
                storage_protocol='iscsi',
                total_capacity_gb=1000,
                free_capacity_gb=999,
                reserved_percentage=0)

        return self._stats
