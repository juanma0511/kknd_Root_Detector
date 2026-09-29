package com.juanma0511.rootdetector.detector

data class PropValueCheck(
    val key: String,
    val suspiciousValues: Set<String>
)

object GetPropCatalog {
    val dangerousRootProps = HardcodedSignals.dangerousRootProps.map { (key, value) ->
        PropValueCheck(key, value.split(",").map(String::trim).filter(String::isNotEmpty).toSet())
    }

    val spoofedBootProps = HardcodedSignals.spoofedBootProps.map { (key, value) ->
        PropValueCheck(key, value.split(",").map(String::trim).filter(String::isNotEmpty).toSet())
    }

    val kernelSuProps = HardcodedSignals.kernelSuProps

    val NLSoundProps = HardcodedSignals.nlSoundProps

    fun collectMatches(getProp: (String) -> String, checks: List<PropValueCheck>): List<String> {
        return checks.mapNotNull { check ->
            val value = getProp(check.key).lowercase()
            if (value.isNotEmpty() && check.suspiciousValues.any { value == it || value.contains(it) }) {
                "${check.key}=$value"
            } else {
                null
            }
        }
    }
}
