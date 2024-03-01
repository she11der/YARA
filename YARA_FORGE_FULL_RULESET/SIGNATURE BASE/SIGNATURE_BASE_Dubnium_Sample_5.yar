rule SIGNATURE_BASE_Dubnium_Sample_5 : FILE
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth (Nextron Systems)"
		id = "09c1aeee-9437-54e9-967f-3c2fcc0736ed"
		date = "2016-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/AW9Cuu"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_dubnium.yar#L64-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0f84f502ba9a4fe304851badfa98d9e8500cdef472d4358cfd327365ac04dda3"
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
		hash6 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
		hash7 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
		hash8 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
		hash9 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"

	strings:
		$s1 = "$innn[i$[i$^i[e[mdi[m$jf1Wehn[^Whl[^iin_hf$11mahZijnjbi[^[W[f1n$dej$[hn]1[W1ni1l[ic1j[mZjchl$$^he[[j[a[1_iWc[e[" fullword ascii
		$s2 = "h$YWdh[$ij7^e$n[[_[h[i[[[\\][1$1[[j1W1[1cjm1[$[k1ZW_$$ncn[[Inbnnc[I9enanid[fZCX" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <9000KB and all of them
}
