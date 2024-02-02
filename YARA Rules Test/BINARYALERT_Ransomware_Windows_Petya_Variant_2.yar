rule BINARYALERT_Ransomware_Windows_Petya_Variant_2
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
		author = "@fusionrace"
		id = "6401fd7e-5ef7-58b5-b8d3-a63c70e8daa3"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_petya_variant_2.yara#L1-L17"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "71b6a493388e7d0b40c83ce903bc6b04"
		logic_hash = "7e04ffd0423cd1288af5c045bb06930abb732c0ea059e329cafc05faecb4f982"
		score = 75
		quality = 78
		tags = ""

	strings:
		$s1 = "dllhost.dat" fullword wide
		$s2 = "\\\\%ws\\admin$\\%ws" fullword wide
		$s3 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\"" fullword wide
		$s4 = "\\\\.\\PhysicalDrive" fullword wide
		$s5 = ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip." fullword wide

	condition:
		3 of them
}