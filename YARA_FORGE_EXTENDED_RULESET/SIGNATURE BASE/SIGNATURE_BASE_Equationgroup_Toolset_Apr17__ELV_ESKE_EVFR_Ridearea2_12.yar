rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ELV_ESKE_EVFR_Ridearea2_12 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "63c7733c-9942-56f3-95cc-f3e72b693739"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L3481-L3498"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0119cd825c02a094ddd76c5cb27bee6cef112f25333eab62017448804b29286e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		hash4 = "e702223ab42c54fff96f198611d0b2e8a1ceba40586d466ba9aadfa2fd34386e"

	strings:
		$x2 = "** CreatePayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
