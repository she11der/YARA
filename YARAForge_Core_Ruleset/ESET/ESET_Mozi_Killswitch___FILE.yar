rule ESET_Mozi_Killswitch___FILE
{
	meta:
		description = "Mozi botnet kill switch"
		author = "Ivan Besina"
		id = "e3d34ae0-de06-5ff4-b44b-44d264b6dd29"
		date = "2023-09-29"
		modified = "2023-10-31"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/mozi/mozi.yar#L32-L51"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "90eaed2f7f5595b145b2678a46ef6179082192215369fa9235024b0ce1574a49"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$iptables1 = "iptables -I INPUT  -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "iptables -I OUTPUT -p tcp --sport 30005 -j DROP"
		$haha = "/haha"
		$networks = "/usr/networks"

	condition:
		all of them and filesize <500KB
}