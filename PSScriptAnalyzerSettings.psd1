# PSScriptAnalyzerSettings.psd1
@{
    ExcludeRules = @(
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingWriteHost',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSAvoidOverwritingBuiltInCmdlets'
    )
}
