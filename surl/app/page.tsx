'use client';

import { Button } from "@/components/ui/button"
import SpotlightCard from "@/components/SpotlightCard"

export default function Page() {
  return (
    <div className="w-full bg-black text-white">
      {/* Hero Section */}
      <section className="min-h-screen flex items-center justify-center py-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
            Advanced URL Threat Intelligence Engine
          </h1>
          <p className="text-xl text-gray-400 mb-8">
            Comprehensive security analysis for URL threats with dynamic and static analysis
          </p>
          <Button className="mt-2 bg-cyan-500 hover:bg-cyan-600 text-black font-bold px-8 py-6">
            Analyze URL
          </Button>
        </div>
      </section>

      {/* Threat Intelligence Pipeline Section */}
      <section className="py-20 px-4 bg-gradient-to-b from-black via-slate-900 to-black">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-16 text-white">
            Threat Intelligence Pipeline
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Card 1: Static URL Analysis */}
            <SpotlightCard 
              className="threat-intelligence-card"
              spotlightColor="rgba(0, 229, 255, 0.2)"
            >
              <div className="relative z-10">
                <div className="text-4xl mb-4 text-cyan-400">
                  <i className="fas fa-magnifying-glass"></i>
                </div>
                <h3 className="text-2xl font-bold mb-4 text-white">1. Static URL Analysis</h3>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 mt-1">●</span>
                    <span>Protocol & TLS Validation</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 mt-1">●</span>
                    <span>Lexical Pattern Inspection</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 mt-1">●</span>
                    <span>WHOIS & Domain Age Check</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 mt-1">●</span>
                    <span>HTML & Script Structure Scan</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 mt-1">●</span>
                    <span>Brand Impersonation Detection</span>
                  </li>
                </ul>
              </div>
            </SpotlightCard>

            {/* Card 2: Sandbox & Dynamic Analysis */}
            <SpotlightCard 
              className="threat-intelligence-card"
              spotlightColor="rgba(168, 85, 247, 0.2)"
            >
              <div className="relative z-10">
                <div className="text-4xl mb-4 text-purple-400">
                  <i className="fas fa-box"></i>
                </div>
                <h3 className="text-2xl font-bold mb-4 text-white">2. Sandbox & Dynamic Analysis</h3>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 mt-1">●</span>
                    <span>Headless Browser Execution</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 mt-1">●</span>
                    <span>DOM Behavior Monitoring</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 mt-1">●</span>
                    <span>Network Request Logging</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 mt-1">●</span>
                    <span>Credential Form Detection</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 mt-1">●</span>
                    <span>Screenshot Capture</span>
                  </li>
                </ul>
              </div>
            </SpotlightCard>

            {/* Card 3: Risk Intelligence Engine */}
            <SpotlightCard 
              className="threat-intelligence-card"
              spotlightColor="rgba(34, 197, 94, 0.2)"
            >
              <div className="relative z-10">
                <div className="text-4xl mb-4 text-green-400">
                  <i className="fas fa-brain"></i>
                </div>
                <h3 className="text-2xl font-bold mb-4 text-white">3. Risk Intelligence Engine</h3>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-start gap-2">
                    <span className="text-green-400 mt-1">●</span>
                    <span>Weighted Risk Scoring Model</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-400 mt-1">●</span>
                    <span>PBH Behavioral Fingerprinting</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-400 mt-1">●</span>
                    <span>Trust Signal Correlation</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-400 mt-1">●</span>
                    <span>Explainable Risk Reporting</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-400 mt-1">●</span>
                    <span>Threat Severity Classification</span>
                  </li>
                </ul>
              </div>
            </SpotlightCard>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-16 text-white">
            Key Features
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-slate-900 p-8 rounded-lg border border-slate-700">
              <h3 className="text-xl font-bold mb-4 text-cyan-400">Real-time Analysis</h3>
              <p className="text-gray-400">Get instant threat assessments with our advanced AI-powered analysis engine.</p>
            </div>
            <div className="bg-slate-900 p-8 rounded-lg border border-slate-700">
              <h3 className="text-xl font-bold mb-4 text-purple-400">Deep Behavioral Inspection</h3>
              <p className="text-gray-400">Detect sophisticated phishing techniques through DOM analysis and behavior monitoring.</p>
            </div>
            <div className="bg-slate-900 p-8 rounded-lg border border-slate-700">
              <h3 className="text-xl font-bold mb-4 text-green-400">Explainable Scoring</h3>
              <p className="text-gray-400">Understand why a URL is flagged with detailed explanations of threat indicators.</p>
            </div>
            <div className="bg-slate-900 p-8 rounded-lg border border-slate-700">
              <h3 className="text-xl font-bold mb-4 text-blue-400">API Integration</h3>
              <p className="text-gray-400">Seamlessly integrate threat intelligence into your security infrastructure.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
