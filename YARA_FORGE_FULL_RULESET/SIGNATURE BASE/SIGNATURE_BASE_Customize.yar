rule SIGNATURE_BASE_Customize : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Customize.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "a69e1234-cc85-5295-a45c-693afdfc368e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L105-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "db556879dff9a0101a7a26260a5d0dc471242af2"
		logic_hash = "f4e0a7342a01411ae060c9d995072518f2e3299af1b0d396bb319eeec42c1519"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
		$s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
		$s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
		$s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii

	condition:
		filesize <24KB and all of them
}
