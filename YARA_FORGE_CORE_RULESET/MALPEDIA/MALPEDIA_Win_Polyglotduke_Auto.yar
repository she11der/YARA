rule MALPEDIA_Win_Polyglotduke_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "afe4cb05-aa94-5225-84e8-b6489c3e26d1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyglotduke"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.polyglotduke_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "37a5b9867f5de08a35688f7a9273792487d4c60d613dec2d499a53b9323d3f00"
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
		$sequence_0 = { e8???????? 488b5608 448bc7 488bc8 488bd8 e8???????? }
		$sequence_1 = { 0fb7f9 492bf3 498bcb 33d2 33c0 }
		$sequence_2 = { 48895c2408 57 4883ec20 488bfa 488bd9 488d0595970000 488981a0000000 }
		$sequence_3 = { 4c8be8 e8???????? 488d0d88120100 e8???????? 488d4c2430 8bd3 4c8bc0 }
		$sequence_4 = { 488be8 498bcc e8???????? 488bcf e8???????? }
		$sequence_5 = { 48894518 e8???????? 488d0dbae30000 48894520 e8???????? 488d0daee30000 }
		$sequence_6 = { 42392c3e 0f849bfaffff 428b143e 4a8d4c3e04 e8???????? 488d0dec0c0100 ba10000000 }
		$sequence_7 = { e8???????? b8cdcccccc f7e5 c1ea02 8d0492 2be8 }
		$sequence_8 = { 99 f77c2428 4863c2 410fb70c46 488b442440 4533f6 66894c4450 }
		$sequence_9 = { 488bf1 8d4301 ba02000000 498be8 }

	condition:
		7 of them and filesize <222784
}
