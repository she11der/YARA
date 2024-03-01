rule SIGNATURE_BASE_HKTL_FRP_Apr20_1
{
	meta:
		description = "Detects FRP fast reverse proxy tool often used by threat groups"
		author = "Florian Roth (Nextron Systems)"
		id = "55483832-0e0b-5c28-8be5-dbd14ddb50e3"
		date = "2020-04-07"
		modified = "2022-11-03"
		reference = "https://github.com/fatedier/frp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_frp_proxy.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "21f91fd99aed8b62d804504889c41ca77567fd345cf4ea0ef00161eefa9324a7"
		score = 70
		quality = 85
		tags = ""
		hash1 = "05537c1c4e29db76a24320fb7cb80b189860389cdb16a9dbeb0c8d30d9b37006"
		hash2 = "08c685c8febb5385f7548c2a64a27bae7123a937c5af958ebc08a3accb29978d"

	strings:
		$x1 = "frp/vendor/github.com/spf13/" ascii
		$x2 = "github.com/fatedier/frp/vendor/" ascii
		$fpg2 = "<html"
		$fpg3 = "<HTML"
		$fpg6 = "<?xml"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
