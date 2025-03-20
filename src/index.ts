import { Agent } from '@openserv-labs/sdk'
import { z } from 'zod'
import axios from 'axios'
import { ethers } from 'ethers'
import 'dotenv/config'

interface AbiItem {
  type: string
  name?: string
  inputs?: { type: string; name?: string }[]
  outputs?: { type: string; name?: string }[]
  stateMutability?: string
  payable?: boolean
  constant?: boolean
}

// **Helper Functions**

/**
 * Fetches the block number closest to the given timestamp using Etherscan API.
 * @param timestamp Unix timestamp in seconds
 * @returns Block number
 */
async function getBlockNumberByTimestamp(timestamp: number): Promise<number> {
  const url = `https://api.etherscan.io/api?module=block&action=getblocknobytime&timestamp=${timestamp}&closest=before&apikey=${process.env.ETHERSCAN_API_KEY}`
  try {
    const response = await axios.get(url)
    if (response.data.status === '1') {
      return parseInt(response.data.result)
    }
    throw new Error('Failed to fetch block number')
  } catch (error) {
    console.error('Error fetching block number:', error)
    throw error
  }
}

/**
 * Fetches all pages of data from an Etherscan API endpoint with pagination.
 * @param baseUrl Base URL for the API call without pagination parameters
 * @returns Array of all results
 */
async function fetchAllPages(baseUrl: string): Promise<any[]> {
  let page = 1
  const offset = 1000 // Etherscan's typical limit per page
  const allData: unknown[] = []
  let hasMoreData = true
  while (hasMoreData) {
    const url = `${baseUrl}&page=${page}&offset=${offset}`
    try {
      const response = await axios.get(url)
      if (response.data.status !== '1') {
        throw new Error(`API error: ${response.data.message}`)
      }
      const data = response.data.result
      if (data.length < offset) hasMoreData = false // Last page
      if (data.length < offset) break // Last page
      page++
    } catch (error) {
      console.error('Error fetching paginated data:', error)
      throw error
    }
  }
  return allData
}

// **Contract Security Scanner Capability**
const contractSecurityScannerCapability = {
  name: 'contract_security_scan',
  description: 'Scans smart contracts for security vulnerabilities and best practices',
  schema: z.object({
    contractAddress: z.string().describe('The smart contract address to analyze'),
    chainId: z
      .number()
      .optional()
      .describe('The blockchain network ID (defaults to Ethereum mainnet)')
  }),
  async run({ args }: { args: { contractAddress: string; chainId?: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY!
    const sourceCodeUrl = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${args.contractAddress}&apikey=${apiKey}`
    const abiUrl = `https://api.etherscan.io/api?module=contract&action=getabi&address=${args.contractAddress}&apikey=${apiKey}`

    try {
      const sourceResponse = await axios.get(sourceCodeUrl)
      const contractData = sourceResponse.data.result[0]
      const isVerified = !!contractData.SourceCode

      const securityIndicators = {
        hasAccessControl: false,
        hasOwnerFunction: false,
        hasEmergencyStop: false,
        usesReentrancyGuard: false,
        hasUpgradeability: false,
        hasTransferOwnership: false,
        hasSelfdestructFunction: false,
        hasUncheckedTransfers: false
      }

      if (isVerified) {
        const source = contractData.SourceCode
        securityIndicators.hasAccessControl = /onlyOwner|Ownable|AccessControl/i.test(source)
        securityIndicators.hasEmergencyStop = /pause|Pausable/i.test(source)
        securityIndicators.usesReentrancyGuard = /nonReentrant|ReentrancyGuard/i.test(source)
        securityIndicators.hasUpgradeability = /Proxy|Upgradeable|delegatecall/i.test(source)
        securityIndicators.hasTransferOwnership = /transferOwnership|Ownable/i.test(source)
        securityIndicators.hasSelfdestructFunction = /selfdestruct/i.test(source)
        securityIndicators.hasUncheckedTransfers =
          source.includes('transfer(') && !/SafeERC20|require\(/i.test(source)
      }

      const abiResponse = await axios.get(abiUrl)
      const abi = JSON.parse(abiResponse.data.result) as AbiItem[]
      securityIndicators.hasOwnerFunction = abi.some(
        item => item.type === 'function' && (item.name === 'owner' || item.name === 'getOwner')
      )

      const riskScore = calculateSecurityRiskScore({ isVerified, ...securityIndicators })
      const riskLevel = getSecurityRiskLevel(riskScore)

      return JSON.stringify({
        contractAddress: args.contractAddress,
        chainId: args.chainId || 1,
        riskLevel,
        riskScore,
        verificationStatus: isVerified ? 'Verified' : 'Unverified',
        securityIndicators,
        recommendations: generateSecurityRecommendations({ isVerified, ...securityIndicators }),
        scanTimestamp: new Date().toISOString()
      })
    } catch (error) {
      console.error('Contract security scan failed:', error)
      return JSON.stringify({
        error: 'Failed to scan contract',
        details: (error as Error).message
      })
    }
  }
}

// **Wallet Analysis Capability**
const walletAnalysisCapability = {
  name: 'analyze_wallet',
  description: 'Analyzes wallet activity for patterns and suspicious transactions',
  schema: z.object({
    walletAddress: z.string().describe('The wallet address to analyze'),
    timeframeInDays: z.number().default(30).describe('Number of days to analyze')
  }),
  async run({ args }: { args: { walletAddress: string; timeframeInDays: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY!
    const timeframeStartTimestamp = Math.floor(Date.now() / 1000) - args.timeframeInDays * 86400

    try {
      const startBlock = await getBlockNumberByTimestamp(timeframeStartTimestamp)
      const txListUrl = `https://api.etherscan.io/api?module=account&action=txlist&address=${args.walletAddress}&startblock=${startBlock}&endblock=99999999&sort=desc&apikey=${apiKey}`
      const erc20TransfersUrl = `https://api.etherscan.io/api?module=account&action=tokentx&address=${args.walletAddress}&startblock=${startBlock}&endblock=99999999&sort=desc&apikey=${apiKey}`

      const [transactions, tokenTransfers] = await Promise.all([
        fetchAllPages(txListUrl),
        fetchAllPages(erc20TransfersUrl)
      ])

      const transactionCount = transactions.length
      const uniqueContractsInteracted = new Set(
        transactions.filter((tx: any) => tx.to).map((tx: any) => tx.to.toLowerCase())
      ).size
      const uniqueTokens = new Set(tokenTransfers.map((tx: any) => tx.tokenSymbol))
      const ethVolume = transactions.reduce(
        (total: number, tx: any) => total + parseFloat(ethers.formatEther(tx.value)),
        0
      )

      const largeTxThreshold = parseFloat(process.env.LARGE_TX_THRESHOLD || '10') // Configurable via env
      const largeTransactions = transactions.filter(
        (tx: any) => parseFloat(ethers.formatEther(tx.value)) > largeTxThreshold
      )
      const unusualTokens = tokenTransfers.filter(
        (tx: any) => !['USDT', 'USDC', 'DAI', 'WETH', 'BTC', 'LINK'].includes(tx.tokenSymbol)
      )

      const firstTxTimestamp = transactions.length
        ? parseInt(transactions[transactions.length - 1].timeStamp)
        : timeframeStartTimestamp
      const lastTxTimestamp = transactions.length
        ? parseInt(transactions[0].timeStamp)
        : Math.floor(Date.now() / 1000)
      const activityDays = (lastTxTimestamp - firstTxTimestamp) / 86400
      const activityFrequency = activityDays > 0 ? transactionCount / activityDays : 0

      return JSON.stringify({
        walletAddress: args.walletAddress,
        timeframeInDays: args.timeframeInDays,
        transactionCount,
        ethVolume: parseFloat(ethVolume.toFixed(4)),
        uniqueContractsInteracted,
        tokenActivity: {
          uniqueTokensCount: uniqueTokens.size,
          tokensList: Array.from(uniqueTokens).slice(0, 10)
        },
        activityMetrics: {
          firstTransaction: new Date(firstTxTimestamp * 1000).toISOString(),
          lastTransaction: new Date(lastTxTimestamp * 1000).toISOString(),
          averageTransactionsPerDay: parseFloat(activityFrequency.toFixed(2))
        },
        suspiciousIndicators: {
          largeTransactionsCount: largeTransactions.length,
          unusualTokensCount: unusualTokens.length,
          riskScore: calculateWalletRiskScore(
            transactionCount,
            largeTransactions.length,
            unusualTokens.length,
            uniqueContractsInteracted
          )
        },
        analysisTimestamp: new Date().toISOString()
      })
    } catch (error) {
      console.error('Wallet analysis failed:', error)
      return JSON.stringify({
        error: 'Failed to analyze wallet',
        details: (error as Error).message
      })
    }
  }
}

// **Token Market Analysis Capability**
const tokenMarketAnalysisCapability = {
  name: 'analyze_token_market',
  description: 'Analyzes token market data for trends and manipulation',
  schema: z.object({
    tokenAddress: z.string().describe('The token contract address'),
    timeframeInDays: z.number().default(7).describe('Number of days to analyze')
  }),
  async run({ args }: { args: { tokenAddress: string; timeframeInDays: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY!
    const timeframeStartTimestamp = Math.floor(Date.now() / 1000) - args.timeframeInDays * 86400

    try {
      const startBlock = await getBlockNumberByTimestamp(timeframeStartTimestamp)
      const transfersUrl = `https://api.etherscan.io/api?module=account&action=tokentx&contractaddress=${args.tokenAddress}&startblock=${startBlock}&endblock=99999999&sort=desc&apikey=${apiKey}`
      const transfers = await fetchAllPages(transfersUrl)

      const provider = new ethers.EtherscanProvider('mainnet', apiKey)
      const ERC20_ABI = [
        'function name() view returns (string)',
        'function symbol() view returns (string)',
        'function totalSupply() view returns (uint256)',
        'function decimals() view returns (uint8)'
      ]
      const contract = new ethers.Contract(args.tokenAddress, ERC20_ABI, provider)
      let tokenInfo: any
      try {
        const [name, symbol, totalSupply, decimals] = await Promise.all([
          contract.name(),
          contract.symbol(),
          contract.totalSupply(),
          contract.decimals()
        ])
        tokenInfo = {
          name,
          symbol,
          totalSupply: totalSupply.toString(),
          decimals: decimals.toString()
        }
      } catch (error) {
        console.warn('Failed to fetch token info via contract:', error)
        tokenInfo = { name: 'Unknown', symbol: 'Unknown', totalSupply: '0', decimals: '18' }
      }

      const transferCount = transfers.length
      const uniqueAddresses = new Set([
        ...transfers.map((tx: any) => tx.from.toLowerCase()),
        ...transfers.map((tx: any) => tx.to.toLowerCase())
      ])
      const holdings: { [key: string]: number } = {}
      transfers.forEach((tx: any) => {
        const from = tx.from.toLowerCase()
        const to = tx.to.toLowerCase()
        const value = parseFloat(ethers.formatUnits(tx.value, parseInt(tx.tokenDecimal || '18')))
        holdings[from] = (holdings[from] || 0) - value
        holdings[to] = (holdings[to] || 0) + value
      })

      const topHolders = Object.entries(holdings)
        .filter(([_, balance]) => balance > 0)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([address, balance]) => ({ address, balance }))
      const totalHoldings = Object.values(holdings)
        .filter(b => b > 0)
        .reduce((sum, b) => sum + b, 0)
      const topHoldersPercentage = topHolders.reduce(
        (sum, { balance }) => sum + (balance / totalHoldings) * 100,
        0
      )

      const transferFrequency = transferCount / args.timeframeInDays
      const suddenSpikes = identifyTransferSpikes(transfers)
      const manipulationRisk = assessMarketManipulationRisk(
        transferFrequency,
        topHoldersPercentage,
        suddenSpikes,
        uniqueAddresses.size
      )

      return JSON.stringify({
        tokenAddress: args.tokenAddress,
        tokenInfo,
        marketMetrics: {
          transferCount,
          uniqueAddressCount: uniqueAddresses.size,
          transfersPerDay: parseFloat(transferFrequency.toFixed(2)),
          topHoldersConcentration: parseFloat(topHoldersPercentage.toFixed(2))
        },
        topHolders,
        marketManipulation: {
          risk: manipulationRisk,
          suspiciousActivityCount: suddenSpikes,
          recommendedAction: getMarketRecommendation(manipulationRisk)
        },
        analysisTimestamp: new Date().toISOString()
      })
    } catch (error) {
      console.error('Token market analysis failed:', error)
      return JSON.stringify({
        error: 'Failed to analyze token market',
        details: (error as Error).message
      })
    }
  }
}

// **Rug Pull Detection Capability**
const rugPullDetectionCapability = {
  name: 'detect_rug_pull',
  description: 'Detects potential rug pull patterns in token contracts and trading activity',
  schema: z.object({
    tokenAddress: z.string().describe('The token contract address to analyze'),
    timeframeInDays: z.number().default(7).describe('Number of days to analyze')
  }),
  async run({ args }: { args: { tokenAddress: string; timeframeInDays: number } }) {
    const apiKey = process.env.ETHERSCAN_API_KEY!
    const timeframeStartTimestamp = Math.floor(Date.now() / 1000) - args.timeframeInDays * 86400

    try {
      const startBlock = await getBlockNumberByTimestamp(timeframeStartTimestamp)
      const sourceCodeUrl = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${args.tokenAddress}&apikey=${apiKey}`
      const transfersUrl = `https://api.etherscan.io/api?module=account&action=tokentx&contractaddress=${args.tokenAddress}&startblock=${startBlock}&endblock=99999999&sort=desc&apikey=${apiKey}`
      const txListUrl = `https://api.etherscan.io/api?module=account&action=txlist&address=${args.tokenAddress}&startblock=${startBlock}&endblock=99999999&sort=desc&apikey=${apiKey}`

      const [sourceResponse, transfers, transactions] = await Promise.all([
        axios.get(sourceCodeUrl),
        fetchAllPages(transfersUrl),
        fetchAllPages(txListUrl)
      ])

      const contractData = sourceResponse.data.result[0]
      const isVerified = !!contractData.SourceCode

      const provider = new ethers.EtherscanProvider('mainnet', apiKey)
      const OWNER_ABI = [
        {
          constant: true,
          inputs: [],
          name: 'owner',
          outputs: [{ name: '', type: 'address' }],
          payable: false,
          stateMutability: 'view',
          type: 'function'
        }
      ]
      let ownerAddress: string | null = null
      try {
        const contract = new ethers.Contract(args.tokenAddress, OWNER_ABI, provider)
        ownerAddress = await contract.owner()
      } catch (error) {
        console.warn('Failed to fetch owner address:', error)
      }

      const source = contractData.SourceCode
      const indicators = {
        isVerified,
        hasLiquidityRemoval: /removeLiquidity|withdrawLiquidity/i.test(source),
        hasMintFunction: source.includes('mint') && !/onlyOwner/i.test(source),
        hasLargeOwnerTransfer: ownerAddress
          ? transfers.some(
              (tx: any) =>
                parseFloat(ethers.formatUnits(tx.value, parseInt(tx.tokenDecimal || '18'))) >
                  1000 && tx.from.toLowerCase() === ownerAddress.toLowerCase()
            )
          : false,
        hasSuddenDrain: detectSuddenDrain(transfers),
        hasSelfDestruct: /selfdestruct/i.test(source)
      }

      const rugPullRisk = calculateRugPullRisk(indicators)
      return JSON.stringify({
        tokenAddress: args.tokenAddress,
        rugPullRiskLevel: getRugPullRiskLevel(rugPullRisk),
        riskScore: rugPullRisk,
        indicators,
        recommendations: generateRugPullRecommendations(indicators),
        analysisTimestamp: new Date().toISOString()
      })
    } catch (error) {
      console.error('Rug pull detection failed:', error)
      return JSON.stringify({
        error: 'Failed to detect rug pull',
        details: (error as Error).message
      })
    }
  }
}

// **Utility Functions**
function calculateSecurityRiskScore({
  isVerified,
  hasAccessControl,
  hasOwnerFunction,
  hasEmergencyStop,
  usesReentrancyGuard,
  hasSelfdestructFunction,
  hasUncheckedTransfers,
  hasUpgradeability
}: any): number {
  let score = 50 // Base score
  if (!isVerified) score += 30
  if (hasAccessControl) score -= 10
  if (hasEmergencyStop) score -= 5
  if (usesReentrancyGuard) score -= 10
  if (hasSelfdestructFunction) score += 20
  if (hasUncheckedTransfers) score += 15
  if (hasUpgradeability && !hasAccessControl) score += 15
  if (hasOwnerFunction && !hasAccessControl) score += 10
  return Math.max(0, Math.min(100, score))
}

function getSecurityRiskLevel(score: number): string {
  if (score >= 75) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function generateSecurityRecommendations({
  isVerified,
  hasAccessControl,
  hasEmergencyStop,
  usesReentrancyGuard,
  hasSelfdestructFunction,
  hasUncheckedTransfers
}: any): string[] {
  const recs: string[] = []
  if (!isVerified) recs.push('Verify contract source code on Etherscan.')
  if (!hasAccessControl) recs.push('Implement access control (e.g., Ownable).')
  if (!hasEmergencyStop) recs.push('Add emergency stop functionality.')
  if (!usesReentrancyGuard) recs.push('Use reentrancy guards for external calls.')
  if (hasSelfdestructFunction) recs.push('Remove selfdestruct to reduce risk.')
  if (hasUncheckedTransfers) recs.push('Use SafeERC20 for token transfers.')
  return recs
}

function calculateWalletRiskScore(
  transactionCount: number,
  largeTransactionsCount: number,
  unusualTokensCount: number,
  uniqueContractsInteracted: number
): string {
  const newWalletRisk = transactionCount < 10 && largeTransactionsCount > 0 ? 30 : 0
  const unusualTokenRisk = Math.min(30, unusualTokensCount * 5)
  const contractDiversityRisk = uniqueContractsInteracted < 3 ? 20 : 0
  const totalRisk = 20 + newWalletRisk + unusualTokenRisk + contractDiversityRisk
  if (totalRisk >= 70) return 'High'
  if (totalRisk >= 40) return 'Medium'
  return 'Low'
}

function identifyTransferSpikes(transfers: any[]): number {
  if (transfers.length < 10) return 0
  const hourlyTransfers: { [key: string]: number } = {}
  transfers.forEach((tx: any) => {
    const hour = Math.floor(parseInt(tx.timeStamp) / 3600) * 3600
    hourlyTransfers[hour] = (hourlyTransfers[hour] || 0) + 1
  })
  const counts = Object.values(hourlyTransfers)
  const avg = counts.reduce((sum, count) => sum + count, 0) / counts.length
  return counts.filter(count => count > avg * 3).length
}

function assessMarketManipulationRisk(
  transferFrequency: number,
  topHoldersPercentage: number,
  suddenSpikes: number,
  uniqueAddressCount: number
): string {
  let riskScore = 0
  if (topHoldersPercentage > 80) riskScore += 30
  else if (topHoldersPercentage > 60) riskScore += 15
  if (transferFrequency > 1000) riskScore += 10
  if (suddenSpikes > 5) riskScore += 20
  if (uniqueAddressCount < 20) riskScore += 20
  if (riskScore >= 40) return 'High'
  if (riskScore >= 20) return 'Medium'
  return 'Low'
}

function getMarketRecommendation(riskLevel: string): string {
  switch (riskLevel) {
    case 'High':
      return 'High risk of manipulation detected; proceed with extreme caution.'
    case 'Medium':
      return 'Moderate risk; conduct further research before engaging.'
    default:
      return 'Low risk; standard precautions apply.'
  }
}

function detectSuddenDrain(transfers: any[]): boolean {
  if (transfers.length < 10) return false
  const hourlyVolumes: { [key: string]: number } = {}
  transfers.forEach((tx: any) => {
    const hour = Math.floor(parseInt(tx.timeStamp) / 3600) * 3600
    const value = parseFloat(ethers.formatUnits(tx.value, parseInt(tx.tokenDecimal || '18')))
    hourlyVolumes[hour] = (hourlyVolumes[hour] || 0) + value
  })
  const volumes = Object.values(hourlyVolumes)
  const avg = volumes.reduce((sum, vol) => sum + vol, 0) / volumes.length
  return volumes.some(vol => vol > avg * 5)
}

function calculateRugPullRisk({
  isVerified,
  hasLiquidityRemoval,
  hasMintFunction,
  hasLargeOwnerTransfer,
  hasSuddenDrain,
  hasSelfDestruct
}: any): number {
  let score = 0
  if (!isVerified) score += 20
  if (hasLiquidityRemoval) score += 25
  if (hasMintFunction) score += 20
  if (hasLargeOwnerTransfer) score += 30
  if (hasSuddenDrain) score += 25
  if (hasSelfDestruct) score += 20
  return Math.min(100, score)
}

function getRugPullRiskLevel(score: number): string {
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

function generateRugPullRecommendations({
  hasLiquidityRemoval,
  hasMintFunction,
  hasLargeOwnerTransfer,
  hasSuddenDrain,
  hasSelfDestruct
}: any): string[] {
  const recs: string[] = []
  if (hasLiquidityRemoval) recs.push('Liquidity removal detected; high risk.')
  if (hasMintFunction) recs.push('Unrestricted minting; potential for abuse.')
  if (hasLargeOwnerTransfer) recs.push('Large owner transfers; possible exit scam.')
  if (hasSuddenDrain) recs.push('Sudden drain detected; rug pull likely.')
  if (hasSelfDestruct) recs.push('Self-destruct present; high risk.')
  return recs
}

// **Agent Setup**
const agent = new Agent({
  systemPrompt: `
    You are a blockchain security expert specialized in:
    1. Smart contract vulnerability analysis
    2. Detecting suspicious wallet activity
    3. Identifying market manipulation in token trading
    4. Assessing security risks in DeFi protocols
    5. Detecting potential rug pulls
    6. Providing actionable security recommendations
    
    Analyze blockchain data carefully and provide clear, concise explanations 
    of security risks with specific recommendations.
  `,
  apiKey: process.env.OPENSERV_API_KEY!
})

agent.addCapabilities([
  contractSecurityScannerCapability,
  walletAnalysisCapability,
  tokenMarketAnalysisCapability,
  rugPullDetectionCapability
])

agent.start()

export default agent
