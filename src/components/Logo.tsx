import React from 'react';

export function Logo({ className = "w-10 h-10" }: { className?: string }) {
  return (
    <img 
      src="https://i.ibb.co/M58YMTk8/20260509-180335.jpg" 
      alt="SYB API Logo" 
      className={`${className} object-contain rounded-xl`}
      loading="lazy"
    />
  );
}
