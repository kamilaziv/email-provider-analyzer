
import React, { useState } from 'react';
import FileUpload from '@/components/FileUpload';
import AnalysisResults from '@/components/AnalysisResults';
import { analyzeEmailsFromCSV } from '@/services/emailAnalyzer';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';

const initialResults = {
  providers: [],
  totalEmails: 0,
  validEmails: 0,
  invalidEmails: 0,
  raw: {},
  errors: []
};

const Index = () => {
  const [results, setResults] = useState(initialResults);
  const [isProcessing, setIsProcessing] = useState(false);
  const [hasResults, setHasResults] = useState(false);

  const handleFileUpload = async (file: File) => {
    setIsProcessing(true);
    
    try {
      const analysisResults = await analyzeEmailsFromCSV(file);
      
      // Short delay for animation effect
      setTimeout(() => {
        setResults(analysisResults);
        setHasResults(true);
        setIsProcessing(false);
        
        if (analysisResults.errors && analysisResults.errors.length > 0) {
          // Show warning toast if there were errors but we still got some results
          toast.warning('Analysis completed with warnings', {
            description: analysisResults.errors[0],
            duration: 5000
          });
        } else if (analysisResults.validEmails > 0) {
          toast.success('Analysis complete', {
            description: `Analyzed ${analysisResults.totalEmails} emails from ${file.name}`
          });
        } else {
          toast.error('No valid emails found', {
            description: 'Please check if the file contains proper email addresses.'
          });
        }
      }, 800);
      
    } catch (error) {
      console.error('Analysis error:', error);
      setIsProcessing(false);
      
      toast.error('Analysis failed', {
        description: error instanceof Error ? error.message : 'Could not process the file. Please check the format and try again.'
      });
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center py-10 px-4">
      <Toaster position="top-center" />
      
      <div className="w-full max-w-5xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold tracking-tight">
            Email Provider Analyzer
          </h1>
          <p className="mt-4 text-xl text-muted-foreground max-w-2xl mx-auto">
            Upload a CSV file with email addresses to analyze them by provider
          </p>
        </div>
        
        <div className="flex flex-col gap-10">
          <div>
            <FileUpload onFileUpload={handleFileUpload} isProcessing={isProcessing} />
          </div>
          
          {isProcessing && (
            <div className="w-full flex justify-center">
              <div className="flex flex-col items-center">
                <div className="w-20 h-1 bg-primary/20 rounded-full overflow-hidden">
                  <div className="h-full w-1/2 bg-primary animated-gradient rounded-full"></div>
                </div>
                <p className="mt-4 text-sm text-muted-foreground">Processing your file...</p>
              </div>
            </div>
          )}
          
          {hasResults && !isProcessing && (
            <div className="fade-in">
              <AnalysisResults results={results} />
            </div>
          )}
        </div>
        
        <footer className="mt-24 text-center text-sm text-muted-foreground">
          <p>Securely analyze your email lists — data never leaves your browser</p>
        </footer>
      </div>
    </div>
  );
};

export default Index;
