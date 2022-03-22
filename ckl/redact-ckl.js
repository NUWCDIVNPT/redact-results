const { XMLParser, XMLBuilder, XMLValidator} = require('fast-xml-parser')
const he = require('he')
const fs = require('fs')

const myArgs = process.argv.slice(2)

const tagValueProcessor = function (tagName, tagValue, jPath, hasAttributes, isLeafNode) {
  he.decode(tagValue)
}
const parseOptions = {
  allowBooleanAttributes: false,
  attributeNamePrefix: "",
  cdataPropName: "__cdata", //default is 'false'
  ignoreAttributes: false,
  parseNodeValue: false,
  parseAttributeValue: false,
  removeNSPrefix: true,
  trimValues: true,
  localeRange: "", //To support non english character in tag/attribute values.
  // // parseTrueNumberOnly: false,
  tagValueProcessor,
  isArray: () => true
}

const subChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWKYZ1234567890'.split('')

function generateChars(length) {
  let result = ''
  for (let i = 0; i < length; i++) {
    result += subChars[Math.floor(Math.random() * subChars.length)]
  }
  return result
}
function generateIp() {
  return (Math.floor(Math.random() * 255) + 1)+"."+(Math.floor(Math.random() * 255))+"."+(Math.floor(Math.random() * 255))+"."+(Math.floor(Math.random() * 255))
}
function generateMac() {
  return "XX:XX:XX:XX:XX:XX".replace(/X/g, function() {
    return "0123456789ABCDEF".charAt(Math.floor(Math.random() * 16))
  })
}

let xmlDataStr
try {
  xmlDataStr = fs.readFileSync(myArgs[0]).toString()
}
catch (e) {
  console.log(`Can't read file`)
  process.exit(1)
}
const parser = new XMLParser(parseOptions)
const cklObj = parser.parse(xmlDataStr)
const assetObj = cklObj?.CHECKLIST?.[0].ASSET?.[0]
if (assetObj) {
  const tags = ['HOST_FQDN', 'HOST_NAME']
  for (const tag of tags) {
    assetObj[tag][0] =  generateChars(assetObj[tag][0].length)
  }
  if (assetObj.HOST_IP[0]) {
    assetObj.HOST_IP[0] = generateIp()
  }
  if (assetObj.HOST_MAC[0]) {
    assetObj.HOST_MAC[0] = generateMac()
  }
}
const iStigArray = cklObj?.CHECKLIST?.[0].STIGS?.[0]?.iSTIG
for (const iStig of iStigArray) {
  const vulnArray = iStig.VULN
  for (const vulnObj of vulnArray) {
    const tags = ['COMMENTS', 'FINDING_DETAILS', 'SEVERITY_JUSTIFICATION']
    for (const tag of tags) {
      vulnObj[tag][0] =  generateChars(vulnObj[tag][0].length)
    }
  }
}
delete cklObj['?xml']

const builder = new XMLBuilder({ format: true });
const output = builder.build(cklObj)
console.log(`<?xml version="1.0" encoding="UTF-8"?>
<!-- redact-ckl -->
${output}`)