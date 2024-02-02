rule MALPEDIA_Win_Royal_Ransom_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "03d0866a-b258-5731-ad57-bc4b0e928885"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_ransom"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.royal_ransom_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "05d0adf9ccc7ed8f53f566dd8191bfd8d7450964340be8e2ce8cbced72447263"
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
		$sequence_0 = { 752f e8???????? 4c8d05d60c1400 ba8b010000 488d0d320c1400 e8???????? 4533c0 }
		$sequence_1 = { e9???????? 2bc3 488d0d2df4dfff 488b8ce9d02c2d00 8064f93dfd f7d8 1ac0 }
		$sequence_2 = { e8???????? 33c0 e9???????? 488b4820 e8???????? 85c0 0f8497020000 }
		$sequence_3 = { e8???????? 488d4e24 448bc8 4c8d0579a80d00 ba09000000 e8???????? 488bcb }
		$sequence_4 = { 8bc2 896c2444 418bfe 83fa02 7d3e e8???????? 4c8d05e7a90f00 }
		$sequence_5 = { 488d1507b51300 41b893040000 e8???????? 41b894040000 488d15efb41300 488bcf e8???????? }
		$sequence_6 = { e8???????? baa6000000 4c89742420 4c8bcd 4c8d05f3a80e00 8d4a93 e8???????? }
		$sequence_7 = { 754a e8???????? 4c8d054e820d00 baa2000000 488d0df2810d00 e8???????? 4533c0 }
		$sequence_8 = { b828000000 e8???????? 482be0 488d15fc4fffff 488d0d5de62000 e8???????? 33c9 }
		$sequence_9 = { e8???????? 85c0 7437 488d05297a0000 4c89742430 4889442428 4c8d0d485c0e00 }

	condition:
		7 of them and filesize <6235136
}