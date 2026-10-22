# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann
# Project: cloudsync-soa-toolkit - https://github.com/mayer-bautechnik/cloudsync-soa-toolkit
"""Source of docs/Consolidated-Findings.pdf.

Requirements: Python 3.9+, reportlab (pip install reportlab), DejaVu fonts (Linux: fonts-dejavu-core; or set
SOA_FONT_DIR to a folder with DejaVuSans.ttf, DejaVuSans-Bold.ttf, DejaVuSans-Oblique.ttf, DejaVuSansMono.ttf).
Version and release date are read from scripts/SoaToolkit.psm1. Run:  python docs/src/build_findings_pdf.py
tools/Set-SoaVersion.ps1 runs it when the version changes. The PDF is built reproducibly (invariant: no creation time,
fixed document ID), and its keywords carry 'cloudsync-soa-toolkit-version=<version> release-date=<date>' in plain text,
which the hygiene check H6 compares with the module.
Keep the content in line with README.md (key findings, upstream issues, references).
"""
import os
import re
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
                                KeepTogether, PageBreak)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
OUT = os.path.join(ROOT, 'docs', 'Consolidated-Findings.pdf')
_psm = open(os.path.join(ROOT, 'scripts', 'SoaToolkit.psm1'), encoding='utf-8-sig').read()
VERSION = re.search(r"\$script:SoaVersion\s*=\s*'([^']+)'", _psm).group(1)
RELEASE = re.search(r"\$script:SoaReleaseDate\s*=\s*'([^']+)'", _psm).group(1)
_candidates = [os.environ.get('SOA_FONT_DIR', ''), '/usr/share/fonts/truetype/dejavu/', '/usr/share/fonts/dejavu/',
               os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Fonts')]
F = next((d for d in _candidates if d and os.path.exists(os.path.join(d, 'DejaVuSans.ttf'))), None)
if not F:
    raise SystemExit('DejaVu fonts not found - set SOA_FONT_DIR')
F = os.path.join(F, '')
pdfmetrics.registerFont(TTFont('Sans', F + 'DejaVuSans.ttf'))
pdfmetrics.registerFont(TTFont('Sans-Bold', F + 'DejaVuSans-Bold.ttf'))
pdfmetrics.registerFont(TTFont('Sans-Oblique', F + 'DejaVuSans-Oblique.ttf'))
pdfmetrics.registerFont(TTFont('Mono', F + 'DejaVuSansMono.ttf'))
from reportlab.pdfbase.pdfmetrics import registerFontFamily
registerFontFamily('Sans', normal='Sans', bold='Sans-Bold', italic='Sans-Oblique', boldItalic='Sans-Bold')

NAVY = colors.HexColor('#1F3864')
LIGHT = colors.HexColor('#EEF2F8')
GRID = colors.HexColor('#C8C8C8')
AMBER = colors.HexColor('#FFF3CD')

base = ParagraphStyle('base', fontName='Sans', fontSize=9.2, leading=12.6, textColor=colors.HexColor('#1B1B1B'))
small = ParagraphStyle('small', parent=base, fontSize=7.8, leading=10.2)
cell = ParagraphStyle('cell', parent=base, fontSize=7.9, leading=10.2)
cellb = ParagraphStyle('cellb', parent=cell, fontName='Sans-Bold', textColor=colors.white)
h1 = ParagraphStyle('h1', parent=base, fontName='Sans-Bold', fontSize=13, leading=17, textColor=NAVY, spaceBefore=10, spaceAfter=5)
h2 = ParagraphStyle('h2', parent=base, fontName='Sans-Bold', fontSize=10.5, leading=14, textColor=NAVY, spaceBefore=8, spaceAfter=3)
title = ParagraphStyle('title', parent=base, fontName='Sans-Bold', fontSize=20, leading=25, textColor=NAVY)
subtitle = ParagraphStyle('subtitle', parent=base, fontSize=11, leading=15, textColor=colors.HexColor('#44546A'))
bullet = ParagraphStyle('bullet', parent=base, leftIndent=11, bulletIndent=2, spaceAfter=2)


def P(t, s=base): return Paragraph(t, s)
def B(t): return Paragraph(t, bullet, bulletText='•')
def code(t): return '<font face="Mono" size="7.6">%s</font>' % t


def table(rows, widths, header=True, zebra=True):
    data = []
    for i, r in enumerate(rows):
        data.append([P(c, cellb if (header and i == 0) else cell) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    st = [('GRID', (0, 0), (-1, -1), 0.4, GRID), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
          ('LEFTPADDING', (0, 0), (-1, -1), 4), ('RIGHTPADDING', (0, 0), (-1, -1), 4),
          ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3)]
    if header: st.append(('BACKGROUND', (0, 0), (-1, 0), NAVY))
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0: st.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#F6F8FB')))
    t.setStyle(TableStyle(st))
    return t


def callout(text, bg=LIGHT, border=NAVY):
    t = Table([[P(text)]], colWidths=[170 * mm])
    t.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), bg), ('LINEBEFORE', (0, 0), (0, -1), 3, border),
                           ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                           ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6)]))
    return t


def on_page(c, doc):
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, A4[1] - 9 * mm, A4[0], 9 * mm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont('Sans-Bold', 8)
    c.drawString(20 * mm, A4[1] - 6 * mm, 'cloudsync-soa-toolkit  |  Consolidated findings')
    c.setFont('Sans', 8)
    c.drawRightString(A4[0] - 20 * mm, A4[1] - 6 * mm, 'Version %s  |  %s' % (VERSION, RELEASE))
    c.setFillColor(colors.HexColor('#666666'))
    c.setFont('Sans', 7.5)
    c.drawString(20 * mm, 10 * mm, 'Preview features - validate in a lab. Independent community work, not affiliated with Microsoft. MPL-2.0')
    c.drawRightString(A4[0] - 20 * mm, 10 * mm, 'Page %d' % doc.page)
    c.restoreState()

doc = BaseDocTemplate(OUT, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
                      title='SOA Toolkit - consolidated findings', author='GEBR. MAYER GmbH + Co. KG, Johannes Lämmermann',
                      subject='Passwordless AD sign-in for users provisioned by Microsoft Entra Cloud Sync',
                      keywords='cloudsync-soa-toolkit-version=%s release-date=%s' % (VERSION, RELEASE), invariant=1)
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='f')
doc.addPageTemplates([PageTemplate(id='p', frames=[frame], onPage=on_page)])
s = []
M = lambda t: '<font face="Mono" size="7.8">%s</font>' % t

s += [Spacer(1, 8 * mm), P('cloudsync-soa-toolkit', title), Spacer(1, 2 * mm),
      P('Passwordless and always able to sign in: cloud users in Active Directory, provisioned by Microsoft Entra Cloud Sync and protected by AD object enforcement', subtitle),
      Spacer(1, 5 * mm)]
s.append(callout('<b>Status %s (%s).</b> Entra ID → AD provisioning and AD object enforcement are <b>preview</b> features. ' % (VERSION, RELEASE) +
                 'Independent community project, not affiliated with Microsoft; validate in a lab. '
                 '<br/><br/><b>Evidence levels.</b> <b>Documented</b> = Microsoft documentation, protocol specification or source code. '
                 '<b>Observed</b> = measured in a domain with the previews (WS2025 DCs, DFL 2025, two writable DCs that are also agent hosts). <b>Inferred</b> = derived.'
                 '<br/><br/><b>Verification status.</b> The findings marked Observed were measured manually by the maintainer. The end-to-end lab validation '
                 'of the 2.x scripts (checklist L1-L20) is in progress - see docs/VALIDATION.md. The project was built with extensive AI assistance and is '
                 'reviewed by the maintainer (README, "How this project was built").'))

s.append(P('1. Executive summary', h1))
for t in [
    '<b>Problem.</b> Users provisioned by Cloud Sync never know an AD password and sign in passwordless (WHfB / FIDO2 via Cloud Kerberos Trust, AVD SSO). '
    'Their AD password still ages, and an <b>expired AD password blocks the passwordless Kerberos sign-in</b> (Documented).',
    '<b>Solution.</b> Make the accounts smart-card-only (SCRIL). Let the DCs roll the hidden secret at the first passwordless sign-in after expiry (automatic rolling). '
    'Control the interval with one fine-grained password policy, and freeze the result with AD object enforcement.',
    '<b>Evidence.</b> Setting SCRIL re-randomizes the secret. With rolling enabled, SCRIL secrets expire on schedule. A WHfB / FIDO2 sign-in via Cloud Kerberos Trust, with AVD SSO and '
    'access to a file share, <b>succeeded after expiry, and the DC rolled the secret during that sign-in</b> (Observed). "Password never expires" disables the rolling (Observed).',
    '<b>Toolkit.</b> Idempotent, reversible setup. Event-triggered onboarding on every writable DC and a reconcile on every agent host (no management server, no single point of failure). '
    'Read-only monitoring, acceptance tests and a step-by-step rollback. The toolkit never rotates, knows or stores a password.',
]:
    s.append(B(t))

s.append(P('2. Target state', h1))
s.append(table([
    ['Object', 'Setting', 'Reason'],
    ['Domain', 'DFL ≥ 2016, msDS-ExpirePasswordsOnSmartCardOnlyAccounts = TRUE', 'Prerequisites for automatic rolling (K9, K13)'],
    ['Cloud user (User_*, msDS-ObjectSoa = Cloud)', '<b>SCRIL set</b>; <b>password never expires cleared</b>; no deny-change ACEs; member of SOA-CloudUsers-PSO',
     'Random secret rolled by the DC (K10, K11, K16); PNE disables rolling (K17); ACEs have no effect (K18); synced groups are universal (K19)'],
    ['PSO-SOA-CloudUsers (precedence 10)', 'Max age 30 days, min age 1 day, min length 64, complexity on, history 24, reversible off, lockout threshold 0',
     'Rolling interval within DISA STIG ≤ 60 days; lockout would only allow DoS against unguessable secrets'],
    ['AD object enforcement', 'Allow-list = all agent gMSAs + toolkit gMSA; Audit phase, then Enforced', 'Only the source of authority changes marked objects'],
], [40 * mm, 70 * mm, 60 * mm]))

s.append(P('3. What the toolkit does', h1))
s.append(table([
    ['Capability', 'Script', 'Writes'],
    ['Prerequisites per DC (engine, KIR, RSoP, container origin) + toolkit prerequisites', 'Test-SoaPrerequisites.ps1', '–'],
    ['Setup: gMSA, batch logon GPO, KIR GPO from Microsoft\'s MSI (one per OS, WMI filter), diagnostics GPO, audit GPO + own narrow msDS-ObjectSoa SACL (monitored), rolling, policy, groups, PSO, delegation, allow-list, tasks', 'Install-SoaToolkit.ps1', 'AD, GPOs, hosts'],
    ['Initial analysis + target state for existing cloud-only / SOA-converted users', 'Install-SoaToolkit.ps1 -Step Conform', 'users, PSO group'],
    ['Onboarding on events 4720 / 5136 by the agent, on every writable DC; reconcile on every agent host', 'Invoke-CloudUserConformance.ps1', 'users, PSO group'],
    ['Monitoring: event log SoaToolkit (2000 / 2001 / 2002), exit code 0/1/2, HTML', 'Watch-CloudUserConformance.ps1', 'event log'],
    ['Impact of Enforced mode', 'Get-SoaEnforcementImpact.ps1', '–'],
    ['Acceptance tests (SCRIL matrix, rolling with a real sign-in, onboarding, enforcement, logon)', 'Test-SoaBehavior.ps1', 'TestUser only'],
    ['Step-by-step rollback (presets Decommission / Full), manifest-driven', 'Uninstall-SoaToolkit.ps1', 'AD, GPOs, hosts'],
], [86 * mm, 60 * mm, 24 * mm]))
s.append(Spacer(1, 2 * mm))
s.append(callout('Every object the toolkit creates carries the marker <b>[SoaToolkit] Managed by SOA Toolkit - do not modify manually</b> and a link to the repository. '
                 'Uninstall removes only objects created by the toolkit; previous values are restored from the manifest.'))

s.append(P('4. Topology - no single point of failure', h1))
s.append(table([
    ['Function', 'Runs on', 'Why'],
    ['Enforcement engine (Microsoft)', 'every writable DC', 'ntdsai.dll'],
    ['Onboarding (event-triggered)', 'every writable DC', 'Security events exist only on the DC that processed the write; the agent may write to any writable DC'],
    ['Reconcile (staggered)', 'every agent host (DC or member server)', 'domain-wide LDAP; needs no DC'],
    ['Monitoring', 'every toolkit host', 'DC-local, agent-local and domain-wide checks'],
    ['Setup / rollback / tests', 'admin workstation', 'no permanent footprint'],
], [45 * mm, 50 * mm, 75 * mm]))
s.append(P('Nothing runs only on the PDC emulator: without rotation every write is idempotent. Microsoft supports the agent on DCs and member servers, recommends Tier-0 hardening of agent hosts, and recommends 3 active agents [R27].', small))

s.append(P('5. Key findings', h1))
s.append(table([
    ['#', 'Finding', 'Evidence'],
    ['K2', 'An expired AD password blocks FIDO2 / WHfB Cloud Kerberos Trust sign-in.', 'Documented [R10]'],
    ['K3', 'Spec: PE never set with SCRIL/PNE; MS-SAMR "never must change" for SCRIL. Describes domains without rolling (see K16).', 'Documented [R14]'],
    ['K5/K6', 'Enforced blocks LDAP modify / modify DN / restore for non-allow-listed identities; add/delete allowed. One stale SID → policy fails to load; max 64 SIDs.', 'Documented [R6]'],
    ['K7', 'A direct userAccountControl mapping is not applied; accountDisabled toggles only 0x2, SCRIL is preserved.', 'Observed'],
    ['K9', 'Rolling needs: attribute TRUE, DFL ≥ 2016, SCRIL, no PNE, expired; writes a random secret and sets pwdLastSet.', 'Documented [R13]'],
    ['K10', '<b>Passwordless sign-in via Cloud Kerberos Trust + AVD SSO succeeds after expiry; the DC rolls the secret during the sign-in.</b>', 'Observed'],
    ['K11', 'Setting SCRIL re-randomizes the secret, pwdLastSet unchanged; rewrite / clear do not re-randomize; random reset moves pwdLastSet.', 'Observed'],
    ['K16', '<b>With rolling enabled, SCRIL secrets expire on schedule</b> (computed expiry = date, PE set at expiry).', 'Observed'],
    ['K17', '"Password never expires" → expiry "never" → no rolling.', 'Observed'],
    ['K18', 'Deny-change ACEs do not change the randomization.', 'Observed'],
    ['K19', 'Synced groups are universal; PSOs apply only to users / global groups → AD-native global group.', 'Documented [R9, R29]'],
    ['K21', '4720 / 5136 are logged only on the DC that processed the write → onboarding on every writable DC.', 'Documented / Inferred'],
], [12 * mm, 128 * mm, 30 * mm]))

s.append(P('6. Microsoft documentation vs. toolkit', h1))
s.append(table([
    ['Topic', 'Microsoft', 'Toolkit'],
    ['Updates, restart, container check, marking', 'manual steps', '<b>same</b>; verified per DC (container incl. originating DC)'],
    ['KIR feature enablement', 'deploy the Group Policy package', '<b>same effect, automated</b>: MSI extracted, ADMX to the central store, one GPO per OS with WMI filter; only the download is manual'],
    ['Policy CN=Cloud', 'Set-CloudSyncSOAPolicy.ps1', '<b>deviation</b>: same object created by the toolkit (Audit); container never created (F2); all agent gMSAs (F6)'],
    ['Mode switch', '"run the script again" (does nothing, F1)', '<b>deviation</b>: keywords written directly, pre-checks, replication wait; Audit first'],
    ['Enablement check', 'Check-CloudSyncSOAPolicy.ps1 (domain-wide only, F3; fixed gMSA DN, F4)', '<b>deviation</b>: per DC ntdsai / KIR / RSoP / event 3095'],
    ['Diagnostics', '"Security Diagnostics = 1"', 'value "2 Security Events" via GPO (F5)'],
    ['Passwordless target state, onboarding, reconcile, monitoring, tests, rollback', '–', '<b>additional</b>'],
], [42 * mm, 52 * mm, 76 * mm]))

s.append(P('7. Rollback and decommissioning', h1))
for t in [
    'Steps (in order): SetModeAudit, StopTasks, RevertUsers (optional, with warning), RemovePso, RemoveAllowList (before RemoveGmsa!), RemovePolicy, RemoveTasks, RemoveAudit, '
    'RemoveDelegation, RemoveBatchLogonGpo, RemoveKirGpo, RemoveDiagnosticsGpo, RemoveGmsa, RemoveGroups, RestoreRolling, RemoveAccounts, Verify.',
    '<b>Decommission</b> preset: the toolkit is removed, while the target state, PSO, policy and KIR GPO stay. <b>Existing users keep working</b> (SCRIL + DC rolling + PSO are native). '
    'New users and SOA conversions are no longer configured.',
    '<b>Full</b> preset: original state as far as possible; users keep SCRIL unless RevertUsers is run explicitly (without SCRIL, rolling stops and the 0x17 problem returns).',
]:
    s.append(B(t))

s.append(P('8. References (selection)', h1))
s.append(table([
    ['ID', 'Source', 'Retrieved'],
    ['R6', 'Configure AD user and group enforcement in Microsoft Entra Cloud Sync (preview), ms.date 2026-08-11', '2026-10-20'],
    ['R7/R8', 'Set-CloudSyncSOAPolicy.ps1 (commit 3f03ef2d) / Check-CloudSyncSOAPolicy.ps1 (commit 0afc4332), github.com/AzureAD/EntraIDGovernance', '2026-10-16'],
    ['R10', 'Passwordless security key sign-in to on-premises resources', '2026-10-15'],
    ['R13', '[MS-SAMS] 3.3.5.7.2 (automatic rolling)', '2026-10-19'],
    ['R14', '[MS-ADTS] msDS-User-Account-Control-Computed', '2026-10-15'],
    ['R19', 'DISA STIG V-243476 (rotation of SCRIL secrets ≤ 60 days)', '2026-10-15'],
    ['R27', 'Microsoft Entra Cloud Sync prerequisites (agent on DC supported, Tier 0, 3 agents)', '2026-10-20'],
    ['R28', 'Use Group Policy to deploy a Known Issue Rollback', '2026-10-20'],
    ['R29', 'AD DS fine-grained password policy step-by-step', '2026-10-20'],
], [14 * mm, 132 * mm, 24 * mm]))
s.append(Spacer(1, 2 * mm))
s.append(P('Repository: https://github.com/mayer-bautechnik/cloudsync-soa-toolkit - full list with URLs in README.md. Copyright (c) 2026 GEBR. MAYER GmbH + Co. KG and Johannes Lämmermann. Licensed under the Mozilla Public License 2.0.', small))
doc.build(s)
print('written', OUT)
