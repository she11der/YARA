rule SIGNATURE_BASE_Dubnium_Sample_7 : FILE
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth (Nextron Systems)"
		id = "6712bd5f-6bbc-5ca0-9fc7-b2013b8f8147"
		date = "2016-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/AW9Cuu"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_dubnium.yar#L109-L131"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "76cf4acee025fcae1dec975a124f4bf808f1f09f99f7fa6a4e965febd6a89e3a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "16f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
		hash2 = "1feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
		hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
		hash4 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		hash5 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
		hash6 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
		hash7 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
		hash8 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"

	strings:
		$s1 = "hWI[$lZ![nJ_[[lk[8Ihlo8ZiIl[[[$Ynk[f_8[88WWWJW[YWnl$$Z[ilf!$IZ$!W>Wl![W!k!$l!WoW8$nj8![8n_I^$[>_n[ZY[[Xhn_c!nnfK[!Z" fullword ascii
		$s2 = "[i_^])[$n!]Wj^,h[,!WZmk^o$dZ[h[e!&W!l[$nd[d&)^Z\\^[[iWh][[[jPYO[g$$e&n\\,Wfg$[<g$[[ninn:j!!)Wk[nj[[o!!Y" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <9000KB and all of them
}
