import "pe"

rule SIGNATURE_BASE_Bypassfirewall_Zip_Folder_Inject
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Inject.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bb31dc53-f3c1-5f8b-84f9-c231a4e1675b"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2125-L2140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
		logic_hash = "6350e11097bc2bb8fb0fbecf6be463aeaf39ad4169d2dd06a57577bf02b515f8"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "Fail To Inject" fullword ascii
		$s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
		$s11 = " Successfully" fullword ascii

	condition:
		all of them
}
