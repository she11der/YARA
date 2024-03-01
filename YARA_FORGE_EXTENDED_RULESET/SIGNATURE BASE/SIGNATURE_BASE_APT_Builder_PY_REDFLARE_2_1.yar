import "pe"

rule SIGNATURE_BASE_APT_Builder_PY_REDFLARE_2_1
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "FireEye"
		id = "74c56ee1-734e-5fdb-beee-6345a5993f68"
		date = "2020-12-01"
		modified = "2020-12-01"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_fireeye_redteam_tools.yar#L1376-L1391"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4410e95de247d7f1ab649aa640ee86fb"
		logic_hash = "0f28fb23c0c1d589466c7c541c8dc588b038d02dded0c66c4a448d1f768c95c5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "<510sxxII"
		$s2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
		$s3 = "parsePluginOutput"

	condition:
		all of them and #s2==2
}
