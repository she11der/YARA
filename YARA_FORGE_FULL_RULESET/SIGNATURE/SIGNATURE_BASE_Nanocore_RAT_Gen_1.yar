rule SIGNATURE_BASE_Nanocore_RAT_Gen_1 : FILE
{
	meta:
		description = "Detetcs the Nanocore RAT and similar malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b007e0ce-e64f-5027-95ff-d178383e3b59"
		date = "2016-04-22"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_nanocore_rat.yar#L8-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "09fab3ef1b4ca9092fd69fb09c4ef759946fcb5b84161441bff797bb4009ed00"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"

	strings:
		$x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
		$x2 = "RunPE1" fullword ascii
		$x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
		$x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
		$x5 = "Monitorinjection" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and (1 of them )) or (3 of them )
}
