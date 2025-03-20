# Shield AI - Blockchain Security Agent

A powerful AI agent built with the [OpenServ SDK](https://github.com/openserv-labs/sdk) that provides comprehensive blockchain security analysis. Shield AI helps users detect vulnerabilities, analyze suspicious activity, and identify potential threats in the crypto ecosystem.

## What Shield AI Can Do

- **Smart Contract Security Analysis**: Scan contracts for vulnerabilities and security best practices
- **Wallet Activity Analysis**: Detect suspicious transactions and patterns in wallet behavior
- **Token Market Analysis**: Identify market manipulation and unusual trading patterns
- **Rug Pull Detection**: Assess token contracts for potential exit scam indicators

## Prerequisites

- Basic knowledge of JavaScript/TypeScript
- Node.js installed on your computer
- An OpenServ account (create one at [platform.openserv.ai](https://platform.openserv.ai))
- An OpenAI API key for local testing
- An Etherscan API key for blockchain data access

## Getting Started

### 1. Set Up Your Project

First, clone this repository to get started:

```bash
git clone https://github.com/yourusername/shield-ai-openserv.git
cd shield-ai-openserv
npm install
```

### 2. Configure Your Environment

Copy the example environment file and update it with your credentials:

```bash
cp .env.example .env
```

Edit the `.env` file to add:
- `OPENSERV_API_KEY`: Your OpenServ API key (required for platform integration)
- `ETHERSCAN_API_KEY`: Your Etherscan API key (required for blockchain data)
- `LARGE_TX_THRESHOLD`: Threshold for flagging large transactions (optional, default: 10 ETH)
- `PORT`: The port for your agent's server (default: 7378)

### 3. Understand the Project Structure

The Shield AI project is organized as follows:

```
shield-ai-openserv/
├── src/
│   └── index.ts       # Agent core logic with blockchain security capabilities
├── .env               # Environment variables
├── package.json       # Project dependencies
└── tsconfig.json      # TypeScript configuration
```

## Understanding Shield AI's Capabilities

Shield AI offers four main capabilities:

### 1. Contract Security Scanner
Analyzes smart contracts for security vulnerabilities and best practices by:
- Checking if the contract is verified on Etherscan
- Detecting access control mechanisms
- Identifying emergency stop functionality
- Checking for reentrancy guards
- Monitoring for high-risk functions like selfdestruct
- Assessing overall contract security risk

### 2. Wallet Analysis
Examines wallet activity to detect suspicious patterns:
- Analyzing transaction history and volume
- Identifying unusual token transactions
- Detecting suspiciously large transfers
- Assessing overall wallet risk score

### 3. Token Market Analysis
Evaluates token trading patterns to identify manipulation:
- Calculating holder concentration
- Detecting sudden trading spikes
- Analyzing trading volume anomalies
- Assessing market manipulation risk

### 4. Rug Pull Detection
Specifically targets indicators of potential exit scams:
- Checking for suspicious contract functions
- Detecting large owner transfers
- Identifying sudden token drains
- Assessing overall rug pull risk

## Testing Locally with `process()`

The `process()` method allows you to test Shield AI locally before deploying:

```typescript
async function main() {
  // Test contract security scanner
  const contractScan = await agent.process({
    messages: [
      {
        role: 'user',
        content: 'Analyze the security of smart contract 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984'
      }
    ]
  })
  console.log('Contract Security Analysis:', contractScan.choices[0].message.content)
  
  // Test wallet analysis
  const walletScan = await agent.process({
    messages: [
      {
        role: 'user',
        content: 'Check if wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 has any suspicious activity'
      }
    ]
  })
  console.log('Wallet Analysis:', walletScan.choices[0].message.content)
}

main()
```

## Exposing Your Local Server with Tunneling

During development, OpenServ needs to reach your Shield AI agent running on your computer. Use a tunneling tool to create a secure connection:

### Using ngrok (recommended)

1. [Download and install ngrok](https://ngrok.com/download)
2. Open your terminal and run:

```bash
ngrok http 7378  # Use your actual port number if different
```

3. Copy the https URL (e.g., `https://abc123.ngrok-free.app`) for platform registration

## Integration with the OpenServ Platform

To test Shield AI on the OpenServ platform:

1. **Start your local server**:
   ```bash
   npm run dev
   ```

2. **Expose your server** with a tunneling tool

3. **Register Shield AI** on the OpenServ platform:
   - Go to Developer → Add Agent
   - Enter "Shield AI" as your agent name
   - Add the capabilities: contract_security_scan, analyze_wallet, analyze_token_market, detect_rug_pull
   - Set the Agent Endpoint to your tunneling URL
   - Create a Secret Key and update your `.env` file

4. **Create a project** on the platform:
   - Projects → Create New Project
   - Add Shield AI to the project
   - Start analyzing blockchain security!

## Example Queries

Here are some examples of how to use Shield AI:

- "Analyze the security risks in contract 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"
- "Is this wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 engaging in suspicious activity?"
- "Check if token 0x6B175474E89094C44Da98b954EedeAC495271d0F shows signs of market manipulation"
- "Is there evidence of a potential rug pull for token 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?"

## Production Deployment

When Shield AI is ready for production:

1. **Build your project**:
   ```bash
   npm run build
   ```

2. **Deploy to a hosting service**:

   **Serverless options**:
   - [Vercel](https://vercel.com/)
   - [Netlify Functions](https://www.netlify.com/products/functions/)
   - [AWS Lambda](https://aws.amazon.com/lambda/)

   **Container-based options**:
   - [Render](https://render.com/)
   - [Railway](https://railway.app/)
   - [Fly.io](https://fly.io/)

3. **Update your agent endpoint** on the OpenServ platform with your production URL

4. **Submit for review** through the Developer dashboard

---

## Future Enhancements

Potential improvements for Shield AI:

- Multi-chain support beyond Ethereum
- DeFi protocol-specific security analysis
- MEV and frontrunning detection
- Historical vulnerability tracking
- Integration with on-chain security oracles

---

Happy building with Shield AI! Enhance blockchain security with the power of AI.