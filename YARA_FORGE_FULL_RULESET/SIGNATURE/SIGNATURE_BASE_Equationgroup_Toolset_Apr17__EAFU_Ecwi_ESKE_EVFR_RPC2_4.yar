rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__EAFU_Ecwi_ESKE_EVFR_RPC2_4 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "9dc9ed95-5233-56e1-b8f1-4f27f43e7e43"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L3338-L3361"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ed6e0e4e5a0849aad64bbc47c047f3fe388052d0ebe89de0257d4422fb39be21"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "3e181ca31f1f75a6244b8e72afaa630171f182fbe907df4f8b656cc4a31602f6"
		hash2 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
		hash3 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash4 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		hash5 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"

	strings:
		$x1 = "* Listening Post DLL %s() returned error code %d." fullword ascii
		$s1 = "WsaErrorTooManyProcesses" fullword ascii
		$s2 = "NtErrorMoreProcessingRequired" fullword ascii
		$s3 = "Connection closed by remote host (TCP Ack/Fin)" fullword ascii
		$s4 = "ServerErrorBadNamePassword" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of ($s*) or 1 of ($x*))
}
