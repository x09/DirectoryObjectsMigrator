"""Configurable, optional FreeIPA profile fields; identities stay engine-owned."""
import base64
import re
from copy import deepcopy
from collections import Counter
from utils.i18n import _

NAME = re.compile(r'^[A-Za-z][A-Za-z0-9-]*$')
PROTECTED = {n.lower() for n in '''cn name distinguishedName objectClass objectGUID objectSid
sIDHistory sAMAccountName userPrincipalName userAccountControl primaryGroupID groupType
member memberOf manager managedBy unicodePwd userPassword pwdLastSet accountExpires
lockoutTime ntSecurityDescriptor servicePrincipalName uidNumber gidNumber loginShell
adminCount allowedAttributes allowedAttributesEffective allowedChildClasses
allowedChildClassesEffective nTSecurityDescriptor supplementalCredentials'''.split()}
TEXT_SYNTAXES = {'1.3.6.1.4.1.1466.115.121.1.'+suffix for suffix in ('15','26','36','44')}
INTEGER = '1.3.6.1.4.1.1466.115.121.1.27'
BOOLEAN = '1.3.6.1.4.1.1466.115.121.1.7'


def default_mappings():
    fields = [('givenName','givenName'),('sn','sn'),('displayName','displayName'),
              ('title','title'),('ou','department'),('street','streetAddress'),('l','l'),
              ('st','st'),('postalCode','postalCode'),('employeeNumber','employeeNumber'),
              ('employeeType','employeeType'),('description','description')]
    rows = [dict(kind='user', source=a, target=b, mode='all', enabled=True) for a,b in fields]
    for source,primary,other in [('mail','mail','otherMailbox'),
            ('telephoneNumber','telephoneNumber','otherTelephone'),('mobile','mobile','otherMobile')]:
        rows.extend([dict(kind='user',source=source,target=primary,mode='primary',enabled=True),
                     dict(kind='user',source=source,target=other,mode='remaining',enabled=True)])
    rows.append(dict(kind='group',source='description',target='description',mode='all',enabled=True))
    rows.append(dict(kind='user',source='ipaSshPubKey',target='altSecurityIdentities',mode='all',enabled=True))
    return rows


def schema_types(connection):
    schema = getattr(getattr(connection, 'server', None), 'schema', None)
    return {str(k).lower(): v for k,v in getattr(schema, 'attribute_types', {}).items()}


def protected_target(name):
    name = name.lower()
    return (name in PROTECTED or name.startswith(('msds-', 'ms-ds-', 'object', 'usn', 'when', 'lastlogon',
                                                'badpwd', 'dscore', 'repl', 'iscritical')))


def source_secret(name):
    name = name.lower()
    return name.startswith(('krb', 'samba', 'ipant', 'ipatoken')) or any(s in name for s in ('password','secret','pwd','credentials','privatekey')) or name == 'userpkcs12'


def ssh_key(value):
    """Accept OpenSSH public-key strings, never certificate/Kerberos identity mappings."""
    fields = value.split()
    if len(fields) < 2 or not fields[0].startswith(('ssh-', 'ecdsa-sha2-', 'sk-')):
        return False
    try:
        blob = base64.b64decode(fields[1], validate=True)
        length = int.from_bytes(blob[:4], 'big')
        return len(blob) > 4+length and blob[4:4+length].decode('ascii') == fields[0]
    except (ValueError, UnicodeError):
        return False


class AttributeMappings:
    def __init__(self, rows, source, destination):
        self.rows = deepcopy(rows)
        self.valid = []
        self.warnings = []
        source_schema, target_schema = schema_types(source), schema_types(destination)
        enabled = [r for r in rows if r.get('enabled', True)]
        targets = Counter((r.get('kind'), str(r.get('target','')).lower()) for r in enabled)
        for row in enabled:
            kind, src, dst, mode = (str(row.get(k,'')) for k in ('kind','source','target','mode'))
            kind_label = {'user': _('User'), 'group': _('Group')}.get(kind, kind)
            label = f'{kind_label}: {src} → {dst}'
            reason = None
            if kind not in ('user','group') or mode not in ('all','primary','remaining') or not NAME.fullmatch(src) or not NAME.fullmatch(dst):
                reason = _('Invalid mapping row or attribute name')
            elif protected_target(dst) or source_secret(src):
                reason = _('Protected or secret attribute cannot be mapped')
            elif dst.lower() == 'altsecurityidentities' and (src.lower() != 'ipasshpubkey' or kind != 'user'):
                reason = _('altSecurityIdentities accepts only ipaSshPubKey for users')
            elif targets[(kind,dst.lower())] > 1:
                reason = _('Multiple mappings use the same destination attribute')
            elif src.lower() not in source_schema:
                reason = _('Source attribute is absent from the readable schema')
            elif dst.lower() not in target_schema:
                reason = _('Destination attribute is absent from the readable schema')
            else:
                definition = target_schema[dst.lower()]
                if any(protected_target(alias) for alias in (getattr(definition, 'name', None) or [])):
                    reason = _('Protected or secret attribute cannot be mapped')
                elif getattr(definition,'no_user_modification',False) or getattr(definition,'obsolete',False):
                    reason = _('Destination attribute is read-only or obsolete')
                elif getattr(definition,'syntax',None) not in TEXT_SYNTAXES | {INTEGER,BOOLEAN}:
                    reason = _('Only text, integer and Boolean profile attributes are supported')
            if reason:
                self.warnings.append(label + ': ' + reason)
            else:
                self.valid.append((row, target_schema[dst.lower()]))

    def source_attributes(self):
        return sorted({row['source'] for row,_ in self.valid})

    def target_attributes(self):
        return sorted({row['target'] for row,_ in self.valid})

    def prepare(self, obj, source_domain, existing=None):
        result, warnings = {}, []
        attrs = {k.lower():v for k,v in obj.attributes.items()}
        existing = {k.lower():v for k,v in (existing or {}).items()}
        rights = {}
        for value in attrs.get('attributelevelrights', []):
            for item in str(value).split(','):
                key,separator,permissions=item.strip().partition(':');rights[key.lower()]=permissions
        for row,definition in self.valid:
            if row['kind'] != obj.kind:
                continue
            src,dst,mode=row['source'],row['target'],row['mode']
            label=f'{src} → {dst}'
            if 'r' not in rights.get(src.lower(),''):
                warnings.append(label+': '+_('Source read permission is not confirmed; attribute skipped'))
                continue
            raw=attrs.get(src.lower(),[])
            items=raw if isinstance(raw,list) else [raw]
            if not items:
                continue
            try:
                strings=sorted({v.decode('utf-8') if isinstance(v,bytes) else str(v) for v in items})
                # Defaults preserve all mail/phone values in primary + secondary rows.
                preferred = None
                primary_rows=[r for r,_ in self.valid if r['kind']==obj.kind and r['source'].lower()==src.lower() and r['mode']=='primary']
                if primary_rows:
                    previous=existing.get(primary_rows[0]['target'].lower())
                    preferred=previous[0] if isinstance(previous,list) and len(previous)==1 else previous
                if preferred not in strings:
                    preferred=obj.name+'@'+source_domain.rstrip('.') if src.lower()=='mail' else None
                chosen=preferred if preferred in strings else strings[0]
                if mode=='primary':strings=[chosen]
                elif mode=='remaining':strings=[v for v in strings if v!=chosen]
                if not strings:continue
                if getattr(definition,'single_value',False) and len(strings)>1:
                    raise ValueError(_('Multiple source values cannot fit a single-valued attribute'))
                syntax=definition.syntax
                if syntax==INTEGER:
                    if not all(re.fullmatch(r'-?\d+',v) for v in strings):
                        raise ValueError(_('Invalid integer value'))
                    output=[int(v) for v in strings]
                elif syntax==BOOLEAN:
                    if not all(v.lower() in ('true','false') for v in strings):
                        raise ValueError(_('Invalid Boolean value'))
                    output=[v.lower()=='true' for v in strings]
                else:
                    if any('\x00' in v for v in strings):raise ValueError(_('NUL characters are not supported'))
                    if syntax.endswith('.26') and any(not v.isascii() for v in strings):raise ValueError(_('Non-ASCII value for an IA5 attribute'))
                    output=strings
                if dst.lower()=='altsecurityidentities' and not all(ssh_key(v) for v in strings):
                    raise ValueError(_('Invalid OpenSSH public key; attribute skipped'))
                result[dst]=output[0] if getattr(definition,'single_value',False) else output
            except (ValueError,UnicodeError) as exc:
                warnings.append(label+': '+str(exc))
        return result,warnings
