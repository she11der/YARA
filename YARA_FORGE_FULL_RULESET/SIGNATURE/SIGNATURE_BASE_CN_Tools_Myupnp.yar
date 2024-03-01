rule SIGNATURE_BASE_CN_Tools_Myupnp : FILE
{
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "394e19d3-882e-5a7c-a3a0-e662bd67955c"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L933-L948"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
		logic_hash = "0bdd0d98dc5218bbe799e5e510c5f27d74a1ef398b09962f4267f846088f726e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1500KB and all of them
}
