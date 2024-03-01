rule SIGNATURE_BASE_WEBSHELL_ASPX_Sportsball
{
	meta:
		description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
		author = "threatintel@volexity.com"
		id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"
		date = "2021-03-01"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hafnium.yar#L159-L180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
		logic_hash = "5ec5e52922e97a3080d397b69b2f42f09daa995271e218ea085fa2ec4e3abad2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
		$uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="
		$var1 = "Result.InnerText = string.Empty;"
		$var2 = "newcook.Expires = DateTime.Now.AddDays("
		$var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
		$var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
		$var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
		$var6 = "<input type=\"submit\" value=\"Upload\" />"

	condition:
		any of ($uniq*) or all of ($var*)
}
