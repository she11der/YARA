rule SIGNATURE_BASE_Sofacy_Fybis_ELF_Backdoor_Gen1 : FILE
{
	meta:
		description = "Detects Sofacy Fysbis Linux Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "c6abf33e-9c5b-5e0f-b7f0-a0741bf9cc3a"
		date = "2016-02-13"
		modified = "2023-01-27"
		reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sofacy_fysbis.yar#L9-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fb5239aa75512c8c83b066e64b75469f90fb22cb0918af1e44edb29e7ab38206"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
		hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"

	strings:
		$x1 = "Your command not writed to pipe" fullword ascii
		$x2 = "Terminal don`t started for executing command" fullword ascii
		$x3 = "Command will have end with \\n" fullword ascii
		$s1 = "WantedBy=multi-user.target' >> /usr/lib/systemd/system/" ascii
		$s2 = "Success execute command or long for waiting executing your command" fullword ascii
		$s3 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" fullword ascii
		$s4 = "rm -f /usr/lib/systemd/system/" ascii
		$s5 = "ExecStart=" fullword ascii
		$s6 = "<table><caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <500KB and 1 of ($x*)) or (1 of ($x*) and 3 of ($s*))
}
