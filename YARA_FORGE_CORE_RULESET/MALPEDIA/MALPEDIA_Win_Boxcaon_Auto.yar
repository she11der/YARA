rule MALPEDIA_Win_Boxcaon_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a730ae2b-b623-5088-86a7-4d1a4eb89ea5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boxcaon"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.boxcaon_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "5b71da83cc61472fd3b6239fea0178674ab4b3cf9a9678dbeeda07cdd88e683a"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 897e14 897e70 c686c800000043 c6864b01000043 c7466890b54000 6a0d e8???????? }
		$sequence_1 = { 8bd3 66899424e0000000 5a 6a50 66899424e2000000 8bd1 66899424e4000000 }
		$sequence_2 = { 8888b8b84000 40 ebe6 ff35???????? }
		$sequence_3 = { 8bec 33c0 8b4d08 3b0cc5408a4000 740a }
		$sequence_4 = { c78424980000003c000000 ff15???????? 56 33ff }
		$sequence_5 = { e8???????? 84c0 741a 8d4c2410 8d8424d8020000 2bc1 }
		$sequence_6 = { 89bc24ac000000 89b424b4000000 c78424980000003c000000 ff15???????? }
		$sequence_7 = { 33c9 66890c06 68???????? 8d442414 50 e8???????? }
		$sequence_8 = { 0020 1f 40 00441f40 0023 d18a0688078a 46 }
		$sequence_9 = { 33c0 c7461407000000 668906 8b4508 8b5810 57 }

	condition:
		7 of them and filesize <256000
}
