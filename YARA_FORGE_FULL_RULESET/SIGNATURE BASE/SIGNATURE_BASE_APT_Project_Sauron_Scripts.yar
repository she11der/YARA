rule SIGNATURE_BASE_APT_Project_Sauron_Scripts
{
	meta:
		description = "Detects scripts (mostly LUA) from Project Sauron report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "575a6f1b-5a4d-5f81-b44a-b7025dbec2a5"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron_extras.yar#L1-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "275ec8de40ae973b4ec4c891c56a70fc2fd05abff258b8015d986d0106506367"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "local t = w.exec2str(\"regedit "
		$x2 = "local r = w.exec2str(\"cat"
		$x3 = "ap*.txt link*.txt node*.tun VirtualEncryptedNetwork.licence"
		$x4 = "move O FakeVirtualEncryptedNetwork.dll"
		$x5 = "sinfo | basex b 32url | dext l 30"
		$x6 = "w.exec2str(execStr)"
		$x7 = "netnfo irc | basex b 32url"
		$x8 = "w.exec(\"wfw status\")"
		$x9 = "exec(\"samdump\")"
		$x10 = "cat VirtualEncryptedNetwork.ini|grep"
		$x11 = "if string.lower(k) == \"securityproviders\" then"
		$x12 = "exec2str(\"plist b | grep netsvcs\")"
		$x14 = "SAURON_KBLOG_KEY ="

	condition:
		1 of them
}
