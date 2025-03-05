
import React, { useState } from 'react';
import FileUpload from '@/components/FileUpload';
import AnalysisResults from '@/components/AnalysisResults';
import { analyzeEmailsFromCSV } from '@/services/emailAnalyzer';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';
import { motion } from 'framer-motion';

// Add framer-motion dependency
<lov-add-dependency>framer-motion@^11.0.0</lov-add-dependency>

const initialResults = {
  providers: [],
  totalEmails: 0,
  validEmails: 0,
  invalidEmails: 0,
  raw: {}
};

const fadeInUp = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { 
      duration: 0.6,
      ease: [0.22, 1, 0.36, 1]
    }
  }
};

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1
    }
  }
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
        
        toast.success('Analysis complete', {
          description: `Analyzed ${analysisResults.totalEmails} emails from ${file.name}`
        });
      }, 800);
      
    } catch (error) {
      console.error('Analysis error:', error);
      setIsProcessing(false);
      
      toast.error('Analysis failed', {
        description: 'Could not process the file. Please check the format and try again.'
      });
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center py-10 px-4">
      <Toaster position="top-center" />
      
      <motion.div 
        className="w-full max-w-5xl mx-auto"
        initial="hidden"
        animate="visible"
        variants={staggerContainer}
      >
        <motion.div 
          className="text-center mb-12"
          variants={fadeInUp}
        >
          <h1 className="text-4xl font-bold tracking-tight">
            Email Provider Analyzer
          </h1>
          <p className="mt-4 text-xl text-muted-foreground max-w-2xl mx-auto">
            Upload a CSV file with email addresses to analyze them by provider
          </p>
        </motion.div>
        
        <motion.div 
          className="flex flex-col gap-10"
          variants={staggerContainer}
        >
          <motion.div variants={fadeInUp}>
            <FileUpload onFileUpload={handleFileUpload} isProcessing={isProcessing} />
          </motion.div>
          
          {isProcessing && (
            <motion.div 
              className="w-full flex justify-center"
              variants={fadeInUp}
            >
              <div className="flex flex-col items-center">
                <div className="w-20 h-1 bg-primary/20 rounded-full overflow-hidden">
                  <div className="h-full w-1/2 bg-primary animated-gradient rounded-full"></div>
                </div>
                <p className="mt-4 text-sm text-muted-foreground">Processing your file...</p>
              </div>
            </motion.div>
          )}
          
          {hasResults && !isProcessing && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
            >
              <AnalysisResults results={results} />
            </motion.div>
          )}
        </motion.div>
        
        <motion.footer 
          className="mt-24 text-center text-sm text-muted-foreground"
          variants={fadeInUp}
        >
          <p>Securely analyze your email lists — data never leaves your browser</p>
        </motion.footer>
      </motion.div>
    </div>
  );
};

export default Index;
