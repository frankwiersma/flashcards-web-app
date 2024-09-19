import React, { useState } from 'react';
import { PlusCircle, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';

const FlashcardApp = () => {
  const [modules, setModules] = useState([]);
  const [newModuleName, setNewModuleName] = useState('');
  const [currentModule, setCurrentModule] = useState(null);
  const [inputText, setInputText] = useState('');
  const [currentCardIndex, setCurrentCardIndex] = useState(0);
  const [showAnswer, setShowAnswer] = useState(false);

  const addModule = () => {
    if (newModuleName.trim()) {
      setModules([...modules, { name: newModuleName, cards: [] }]);
      setNewModuleName('');
    }
  };

  const deleteModule = (index) => {
    const updatedModules = modules.filter((_, i) => i !== index);
    setModules(updatedModules);
    if (currentModule === index) {
      setCurrentModule(null);
    }
  };

  const addCards = () => {
    if (currentModule !== null && inputText.trim()) {
      const newCards = inputText.split('\n').map(line => {
        const [question, answer] = line.split(':').map(part => part.trim());
        return { question, answer };
      }).filter(card => card.question && card.answer);

      const updatedModules = [...modules];
      updatedModules[currentModule].cards.push(...newCards);
      setModules(updatedModules);
      setInputText('');
    }
  };

  const nextCard = () => {
    if (currentModule !== null && modules[currentModule].cards.length > 0) {
      setCurrentCardIndex((prevIndex) => 
        (prevIndex + 1) % modules[currentModule].cards.length
      );
      setShowAnswer(false);
    }
  };

  return (
    <div className="p-4 max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">Flashcard Web App</h1>
      
      <div className="mb-4 flex">
        <Input
          type="text"
          value={newModuleName}
          onChange={(e) => setNewModuleName(e.target.value)}
          placeholder="New module name"
          className="mr-2"
        />
        <Button onClick={addModule}>
          <PlusCircle className="mr-2 h-4 w-4" /> Add Module
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-2 mb-4">
        {modules.map((module, index) => (
          <Button
            key={index}
            onClick={() => setCurrentModule(index)}
            variant={currentModule === index ? "default" : "outline"}
            className="relative"
          >
            {module.name}
            <X
              className="h-4 w-4 absolute top-1 right-1 cursor-pointer"
              onClick={(e) => {
                e.stopPropagation();
                deleteModule(index);
              }}
            />
          </Button>
        ))}
      </div>

      {currentModule !== null && (
        <div className="mb-4">
          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Enter cards (question: answer)"
            className="w-full h-32 p-2 border rounded"
          />
          <Button onClick={addCards} className="mt-2">Add Cards</Button>
        </div>
      )}

      {currentModule !== null && modules[currentModule]?.cards.length > 0 && (
        <Card className="mt-4">
          <CardContent className="p-4">
            <div className="text-center">
              <p className="text-lg font-semibold mb-2">
                {showAnswer
                  ? modules[currentModule].cards[currentCardIndex].answer
                  : modules[currentModule].cards[currentCardIndex].question}
              </p>
              <Button onClick={() => setShowAnswer(!showAnswer)} className="mr-2">
                {showAnswer ? 'Show Question' : 'Show Answer'}
              </Button>
              <Button onClick={nextCard}>Next Card</Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default FlashcardApp;
