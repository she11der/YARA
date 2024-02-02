rule ESET_IIS_Group09
{
	meta:
		description = "Detects Group 9 native IIS malware family"
		author = "ESET Research"
		id = "69d176bc-73b1-5c4d-bb7e-463d26e8e6a9"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/badiis/badiis.yar#L339-L387"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "5f89f9488221b8db8d493b3c23b7f5edd957c15511148eca890558886c128192"
		score = 75
		quality = 76
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "FliterSecurity.dll"
		$i2 = {56565656565656565656565656565656}
		$i3 = "app|hot|alp|svf|fkj|mry|poc|doc|20" xor
		$i4 = "yisouspider|yisou|soso|sogou|m.sogou|sogo|sogou|so.com|baidu|bing|360" xor
		$i5 = "baidu|m.baidu|soso|sogou|m.sogou|sogo|sogou|so.com|google|youdao" xor
		$i6 = "118|abc|1go|evk" xor
		$s1 = "AVCFuckHttpModuleFactory"
		$s2 = "X-Forward"
		$s3 = "fuck32.dat"
		$s4 = "fuck64.dat"
		$s5 = "&ipzz1="
		$s6 = "&ipzz2="
		$s7 = "&uuu="
		$s8 = "http://20.3323sf.c" xor
		$s9 = "http://bj.whtjz.c" xor
		$s10 = "http://bj2.wzrpx.c" xor
		$s11 = "http://cs.whtjz.c" xor
		$s12 = "http://df.e652.c" xor
		$s13 = "http://dfcp.yyphw.c" xor
		$s14 = "http://es.csdsx.c" xor
		$s15 = "http://hz.wzrpx.c" xor
		$s16 = "http://id.3323sf.c" xor
		$s17 = "http://qp.008php.c" xor
		$s18 = "http://qp.nmnsw.c" xor
		$s19 = "http://sc.300bt.c" xor
		$s20 = "http://sc.wzrpx.c" xor
		$s21 = "http://sf2223.c" xor
		$s22 = "http://sx.cmdxb.c" xor
		$s23 = "http://sz.ycfhx.c" xor
		$s24 = "http://xpq.0660sf.c" xor
		$s25 = "http://xsc.b1174.c" xor

	condition:
		ESET_IIS_Native_Module_PRIVATE and any of ($i*) and 3 of ($s*)
}